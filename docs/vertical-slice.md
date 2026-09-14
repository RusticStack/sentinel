# The vertical slice under stress (W09)

W09 does not add a subsystem; it exercises the ones Part 04 built, together, under the things that go wrong, and records what held. Two additions were needed to make the scenarios drivable and one defect was found.

## What is exercised, and where

| Scenario | Where it is proven |
|---|---|
| success and command failure, through the API, with the log | `crates/sentinel-worker/tests/slice.rs` |
| duplicate offer (at-least-once delivery) | `crates/sentinel-link/tests/duplicate.rs`: a hand-rolled controller sends the same offer twice; the worker acknowledges twice and its executor is asked once |
| lost acknowledgement | `crates/sentinel-link/tests/link.rs` (W02): an unread offer lapses after the ack timeout and is re-offered under a higher fence; the late acknowledgement is stale |
| cancel during preparation | `slice.rs`: the cancel lands between checkout and image pull; no container starts; the verdict is `canceled`, not a preparation failure; the log is closed and the spool removed |
| cancel during run, graceful and forced | `crates/sentinel-worker/tests/end_to_end.rs` (W06) |
| worker restart | `end_to_end.rs` (W07): leftovers reconciled, the pre-crash log delivered, the attempt abandoned |
| controller restart under a running job | `slice.rs`: same store, log store, identity and address; startup reconciliation leaves the live lease alone; the worker reconnects and the job completes once |
| stale lease | `crates/sentinel-store/tests/dispatch.rs` (W06): expiry by lapse and by overrun; the late report refused; nothing replayed |
| network loss under a running job | `slice.rs`: the controller drops the session (`Handle::disconnect`); the worker keeps the attempt, reconnects with back-off, resends its log from the cursor; the log has every frame once |
| no duplicate healthy-session execution | `slice.rs`: every job's fence is 1 and the executor started exactly one attempt per job across the cancel, the loss and the restart |
| no orphaned owned processes after recovery | `slice.rs` and `end_to_end.rs`: `podman::owned` empty, no workspace, spool or marker left |

## What W09 added

- `Controller::handle().disconnect(worker)`: close a worker's session from the controller's side. Its leases stay until they expire and it may reconnect at once — an operator's way to force a fresh session, and the test's way to lose the network.
- `Executor::set_prepare_hold(duration)`: a pause between checkout and image pull, zero in production, so a cancel arriving during preparation can be exercised deterministically instead of by racing a pull.

## What W09 found

A cancel that landed during preparation was classified `Preparation` (an infrastructure failure attributed to nobody) rather than `Canceled`, and an attempt that never reached its steps never closed its log, leaving an empty spool behind for reconciliation to find. Both are fixed in `attempt::run`: the preparation-failure path checks the cancel flag first and closes the output on every path.

## What is still not covered

The slice runs the components in one process with real containers, not the two binaries; the binaries are exercised by `crates/sentinel/tests/cli.rs` (enrollment, the API, clean signals) but not under these failures. A stale lease and a lease-guard expiry on the worker are proven at the store and unit level, not with a 30 s wait in the slice. Load, Tailcat and relayed paths, slow or full disks and a real network partition remain [blocked by](parts-01-02-audit.md) the hardware and network environments the audit names.

## Verification

Executed on 2026-09-14 as `sentinelbench` (WSL2, Podman 4.9.3 rootless, cgroup v2): `slice.rs` — five jobs through the API against a busybox image by digest; `ok` passed with `hello\ndone\n`, `bad` failed `command_failed` with `boom` on stderr, `held` cancelled during its preparation hold as `canceled`, `long` passed across a dropped and re-established session with `start\nend\n` once, `slow` passed across a controller restart whose reconciliation settled nothing; five `Started` notices, every fence 1, nothing owned or left; the whole run in about 22 s. `duplicate.rs` on Windows and Linux. The W06/W07 end-to-end and the W02 link suites unchanged and green.
