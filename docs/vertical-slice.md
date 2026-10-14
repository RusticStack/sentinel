# The vertical slice under stress

The worker, link, executor and store are exercised together under the failures that matter, mostly in `crates/sentinel-worker/tests/slice.rs`. This page lists each scenario and where it is proven.

## What is exercised, and where

| Scenario | Where it is proven |
|---|---|
| success and command failure, through the API, with the log | `crates/sentinel-worker/tests/slice.rs` |
| duplicate offer (at-least-once delivery) | `crates/sentinel-link/tests/duplicate.rs`: a hand-rolled controller sends the same offer twice; the worker acknowledges twice and its executor is asked once. Across beats and sessions the link's dedup set is trimmed to what the executor holds, and the executor itself re-acknowledges an offer of an attempt it already holds or awaits instead of starting it again (`Executor::offered`) |
| a spec that never arrives, or arrives late after a lost ack write | `crates/sentinel-store/tests/execution.rs`: the spec is served only once the acknowledgement is durable, and an acknowledged attempt that never started is handed back to the queue rather than failed; the worker's re-ask and hand-back are in `sentinel-worker::executor` |
| lost acknowledgement | `crates/sentinel-link/tests/link.rs`: an unread offer lapses after the ack timeout and is re-offered under a higher fence; the late acknowledgement is stale |
| cancel during preparation | `slice.rs`: the cancel lands between checkout and image pull; no container starts; the verdict is `canceled`, not a preparation failure; the log is closed and the spool removed |
| cancel during run, graceful and forced | `crates/sentinel-worker/tests/end_to_end.rs` |
| worker restart | `end_to_end.rs`: leftovers reconciled, the pre-crash log delivered, the attempt abandoned |
| controller restart under a running job | `slice.rs`: same store, log store, identity and address; startup reconciliation leaves the live lease alone; the worker reconnects and the job completes once |
| stale lease | `crates/sentinel-store/tests/dispatch.rs`: expiry by lapse and by overrun; the late report refused; nothing replayed |
| network loss under a running job | `slice.rs`: the controller drops the session (`Handle::disconnect`); the worker keeps the attempt, reconnects with back-off, resends its log from the cursor; the log has every frame once |
| no duplicate healthy-session execution | `slice.rs`: every job's fence is 1 and the executor started exactly one attempt per job across the cancel, the loss and the restart |
| no orphaned owned processes after recovery | `slice.rs` and `end_to_end.rs`: `podman::owned` empty, no workspace, spool or marker left |

## Test hooks

- `Controller::handle().disconnect(worker)` closes a worker's session from the controller's side. Its leases stay until they expire and it may reconnect at once: an operator's way to force a fresh session, and the tests' way to lose the network.
- `Executor::set_prepare_hold(duration)` pauses between checkout and image pull (zero in production), so a cancel during preparation is exercised deterministically instead of by racing a pull.

A cancel that lands during preparation is classified `canceled`, not a preparation failure, and an attempt that never reaches its steps still closes its log (`attempt::run`).

## What is not covered

The slice runs the components in one process with real containers, not the two binaries; the binaries are exercised by `crates/sentinel/tests/cli.rs` (enrollment, the API, clean signals) but not under these failures. A stale lease and a lease-guard expiry on the worker are proven at the store and unit level, not with a 30 s wait in the slice. Load, Tailcat and relayed paths, slow or full disks and a real network partition need hardware and network environments that are not available ([parts-01-02-audit](parts-01-02-audit.md)).

## Verification

`slice.rs` runs seven jobs through the API against a busybox image by digest: `ok` passes, `bad` fails `command_failed`, `pack` publishes its declared artifact, `must` fails `publication` for a required artifact that matched nothing, `held` is canceled during its preparation hold, `long` passes across a dropped and re-established session with its log delivered once, and `slow` passes across a controller restart whose reconciliation settles nothing. It asserts seven `Started` notices, every fence 1, and nothing owned or left behind. It needs rootless Podman and runs on the VPS; `duplicate.rs` runs on Windows and Linux.
