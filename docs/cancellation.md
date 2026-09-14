# Cancellation, termination, timeouts and lease expiry (W06)

Implemented in `sentinel-store::dispatch` (`cancel`, `cancel_run`, `cancel_requested`, `expired`, `expire`, `sweep_queue_timeouts`), the controller's dispatch pass, the `cancel` list on the heartbeat's `Pong`, `sentinel-worker::podman::terminate_named` and the executor's cancel and lease watchdog, with migration **16** and `sentinel admin cancel`.

## Cancellation is desired state

`dispatch::cancel` records `cancel_requested` on the job first — durable, never cleared, and a cancelled job cannot be rerun — and then does one of two things:

- **Unstarted** (`blocked` or `queued`): `CancelBeforeStart` moves it to `canceled` in the same transaction. Placement already skips any job with cancellation desired, so nothing starts after the decision.
- **Owned by a worker**: nothing else happens on the controller. The attempt stays the worker's, its lease keeps renewing, and the worker is told with **every heartbeat** (`Pong { cancel }`, from `dispatch::cancel_requested` over the attempts it holds) until it reports — a missed pong changes nothing. The worker's own report, `Failed(Canceled)`, is what ends the job, releases the capacity and decides the dependents.

`cancel_run` applies this to every non-terminal job of a run. `sentinel admin cancel --job|--run` is the host-local way in; the API (W08) uses the same calls.

## Termination on the worker

`Executor::cancel(attempt)` sets the attempt's cancel flag first, so a step that ends on its own meanwhile is still classified `Canceled` — the desired state wins over the incidental exit status — and then, off the session thread, `podman::terminate_named`:

1. `podman inspect` gives the container's init pid and host cgroup path.
2. **Graceful:** `SIGTERM` to every process in the container's cgroup **except the keepalive** (`cgroup.procs`, read from the host; rootless, so the processes are the worker account's and the signal needs no privilege). The keepalive is spared on purpose: if the container's init died, the runtime would `SIGKILL` everything at once and there would be no grace.
3. Wait up to the grace period (`DEFAULT_CANCEL_GRACE`, 30 s; `Executor::set_cancel_grace`) for the cgroup to empty of step processes.
4. **Forced:** if anything is still there, `podman stop -t 0` and `podman rm -f` — the whole container and process group, not one pid.

A cancel that lands during preparation — between checkout and image pull, before any container exists — ends the attempt as `canceled` too, with its (empty) log closed. Otherwise the step's `exec` returns as the process dies (signal 15, or the script's own exit); the attempt loop sees the flag, records the step `Signaled`/`NotRun` for the rest, finalizes as usual — workspace and container gone, log closed — and reports `Failed(Canceled)`. `Notice::Canceled { forced }` says which way it went.

## Timeouts

- **Execution:** the worker's, per step and bounded by the job's budget ([executor](executor.md#steps-w04)); `ExecutionTimeout`, `timed_out`.
- **Controller backstop:** an attempt still acknowledged past `acked + job.timeout + EXECUTION_GRACE_MS` (10 min) is treated like an expired lease — the worker is renewing but not enforcing, and that is an infrastructure failure, not the repository's.
- **Queue:** a job `queued` for longer than `QUEUE_TIMEOUT_MS` (6 h, server policy) is `QueueTimedOut` → `timed_out`, and its dependents are decided (skipped) in the same transaction. Swept every dispatch pass over the `jobs_queued_since` partial index.

## Lease expiry and capacity release

Every dispatch pass (a wake or the 2 s reconciliation) runs `dispatch::expired`: held attempts whose `lease_until` has passed (over the `attempts_held_by_lease` partial index) plus the execution overruns above. Each is `expire`d: `LeaseExpired` through the state machine as the controller, the reservation released, the dependents decided. The job ends `infra_failed`. **It is never re-queued on its own**: whether the attempt's side effects happened is unknown, and the plan forbids replaying uncertain work; a rerun is an explicit operator decision. A late report from the expired attempt is refused (the attempt is no longer held), and the worker is told to stop it on its next beat.

On the worker, `Executor::renewed` turns every granted `lease_until` into a monotonic deadline less `LEASE_GUARD` (5 s); a watchdog thread checks it every second. Once it passes with no renewal — the session was lost longer than the lease — every live attempt is ended, forced, and **nothing is reported**: the controller has expired them and any report would be stale. The worker acts before the controller could have expired it, never after, so no two workers can believe they own the same attempt.

A worker that disconnects briefly keeps its work: acknowledged leases run to their deadline, the spool holds the log, and a reconnect within the lease resumes renewing.

## What is not here yet

Reconciliation after a restart is in [reconciliation](reconciliation.md). Concurrency groups and supersession cancellation (cancel the older run of the same PR) are C-tasks that call `cancel_run`. Tenant suspension already cancels through the same desired state ([tenancy](tenancy.md)).

## Verification

`crates/sentinel-store/tests/dispatch.rs`: an unstarted job is `canceled` at once and a second cancel is a no-op; a leased and acknowledged job records the request, stays leased, appears in `cancel_requested` for its worker (not for another), ends `canceled` on the worker's report with capacity released, and cannot be rerun; `cancel_run` touches only the non-terminal jobs. Expiry: not expired while the lease holds or renews; an attempt renewed past its job's timeout plus the grace is expired by the backstop; expiry is `LeaseExpired`/`infra_failed`, releases capacity, skips the dependent, re-queues nothing, refuses the late report, is not found twice, and puts the attempt on the worker's stop list; a plain lapse expires by the deadline alone. Queue timeouts fire at exactly the policy, classify `QueueTimeout`, skip dependents and do not repeat.

`crates/sentinel-link/tests/link.rs`: a cancel recorded on the controller reaches the connected worker on its next beat while the job stays leased; the worker's `Failed(Canceled)` ends it; a worker that stops cleanly leaves its running job's lease in place.

`crates/sentinel-worker/tests/end_to_end.rs` (as `sentinelbench`, rootless Podman, grace 2 s): `polite` (`sleep 300`) and `stubborn` (`trap "" TERM; while :; do sleep 1; done`) are cancelled after their first output is on the controller; both reach `canceled` in well under the 30 s bound, `polite` gracefully (`forced: false`) and `stubborn` by the forced stop (`forced: true`), their summaries name the cancel and mark later steps `NotRun`, and no container is left in the runtime.
