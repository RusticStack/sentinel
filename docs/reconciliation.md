# Crash and restart reconciliation (W07)

Implemented in `sentinel-store::dispatch` (`reconcile_startup`, `abandon`), `Controller::start` (which runs the former before admitting anyone), `sentinel-worker::recovery` with the attempt markers the executor keeps, and the `Abandon` message of the [worker link](worker-link.md).

## The rows are the truth

Nothing about a lease, a reservation, an offer or a log lives only in memory. A controller that restarts reads the same rows the last one wrote, so reconciliation is not a rebuild — it is settling, once, what could only have moved with a controller running:

| Found at start | Settled as |
|---|---|
| an acknowledged attempt whose lease passed while the controller was down | `LeaseExpired` → `infra_failed`, capacity released, dependents decided |
| an offer never acknowledged within the ack timeout | lapsed back to the queue (it never ran, so replaying it is safe) |
| an acknowledged attempt of a worker revoked meanwhile | `Reconciled` → `infra_failed` (no session will ever report it) |
| an acknowledged attempt whose lease still holds | left alone: the worker may reconnect within it and keep renewing |

One transaction, before the listener binds. `Controller::reconciled()` reports the counts and `link_listening` logs them. Log files with a torn tail are cut on first open ([logs](logs.md)) and the worker, whose cursor never passed the missing frame, resends it.

**Nothing found this way is re-queued if it may have run.** The plan forbids replaying uncertain side-effecting work; an infrastructure failure with a rerun available to the operator is the honest outcome.

## The worker keeps a marker

The moment an attempt is spawned, before checkout starts, the executor writes `<data_dir>/attempts/<attempt>` holding the fence. The marker outlives the attempt's end: it is removed only once the terminal report has actually been **sent** — a crash between "passed" and "delivered" is a crash the next process must reconcile, not one to forget.

On start, before a single offer is taken, `recovery::recover`:

1. removes every container the runtime still holds under this worker's label (a container running unobserved is not a job; it is a leak);
2. destroys every leftover workspace (and the askpass helper of a checkout that was under way) — a fresh attempt gets a fresh one;
3. discards a spool that has no marker (its attempt's end was reported; only the spool removal was cut short);
4. keeps every marker with its fence and its spool, if any, as a **leftover**.

Once the session is up, each leftover is handed to the controller on a recovery thread: the spool's frames are delivered from the cursor and the log closed (the attempt is still held, so they are accepted — or refused if its lease already expired, in which case the spool is dropped), then `Abandon { attempt, fence }`, then the marker goes. `Notice::Abandoned { log_delivered }` says what happened. If the session is lost midway, the leftover waits for the next attach.

`dispatch::abandon` requires the attempt to be held by that worker under that fence — a stale claim or a foreign worker is refused — and then: an attempt that was **acknowledged** is `Reconciled` (`infra_failed`); one that was only offered lapses back to the queue. The steps are never run again by this path.

## What is not here yet

Resumable *artifact* uploads and cache publication are D-tasks; the spool is the only upload today, and it resumes from its cursor. Reconciliation of a controller's own half-written objects is a D-task with the object store. A worker whose data directory was lost has nothing to reconcile with: its held attempts expire on the controller.

## Verification

`crates/sentinel-store/tests/dispatch.rs`: a start after the lease passed expires the acknowledged attempts (including a revoked worker's), lapses the unanswered offer back to the queue and leaves the live one; a start inside the lease lapses the unanswered offer by the ack timeout and reconciles the revoked worker's attempt; abandonment is refused for a wrong fence and a foreign worker, reconciles an acknowledged attempt, lapses an unacknowledged one, and the stale completion is refused afterwards.

`crates/sentinel-worker/tests/recovery.rs` (any Linux): markers record fences; recovery destroys workspaces and an askpass helper, discards the spool without a marker, keeps the marked attempt's spool with its frames and returns it as pending.

`crates/sentinel-link/tests/link.rs`: over the link, an abandonment under the wrong fence is counted stale and changes nothing; under the right one the job is `infra_failed`.

`crates/sentinel-worker/tests/end_to_end.rs` (as `sentinelbench`): with a held, acknowledged attempt whose marker, running container, half-written workspace and spool were left by "the previous process", a new executor removes the container and the workspace before taking any offer, connects under the same identity, delivers the pre-crash frame so the log is complete, abandons the attempt — the job ends `infra_failed` with class `Reconciled`, nothing re-ran — and leaves no marker, spool or container behind.
