# Cancellation, termination, timeouts and lease expiry (W06)

Implemented in `sentinel-store::dispatch` (`cancel`, `cancel_run`, `cancel_requested`, `expired`, `expire`, `sweep_queue_timeouts`), the controller's dispatch pass, the `cancel` list on the heartbeat's `Pong`, `sentinel-worker::podman::terminate_named` and the executor's cancel and lease watchdog, with migration **16** and `sentinel admin cancel`.

## Cancellation is desired state

`dispatch::cancel` records `cancel_requested` on the job first — durable, and never cleared by an operator or API cancel: a cancelled job cannot be rerun. The one exception is a GitHub check-run rerequest, which deliberately starts a cancelled job over and resets the flag with it ([checks](checks.md#rerequests-and-lifecycle-reconciliation-g05)). It then does one of two things:

- **Unstarted** (`blocked` or `queued`): `CancelBeforeStart` moves it to `canceled` and its dependents are decided (skipped) in the same transaction — like every other terminal edge, so a run never waits on a dependent nothing will release. Placement already skips any job with cancellation desired, so nothing starts after the decision.
- **Offered, not yet started** (`leased`): the offer goes back one way or another — declined, never acknowledged, lost with the session, or handed back because its spec never arrived — and at that moment the job ends `canceled` with its dependents decided, instead of returning to the queue for a placement it can no longer get. An acknowledged attempt that asks for its spec with the cancel already recorded is settled the same way before anything runs.
- **Running on a worker**: nothing else happens on the controller. The attempt stays the worker's, its lease keeps renewing, and the worker is told with **every heartbeat** (`Pong { cancel }`, from `dispatch::cancel_requested` over the attempts it holds) until it reports — a missed pong changes nothing. The worker's own report, `Failed(Canceled)`, is what ends the job, releases the capacity and decides the dependents. A worker `Failed(Canceled)` for a job that never had cancellation requested is the worker ending it on its own, and is recorded as `Failed(Runtime)` (`infra_failed`), never as the user's cancel.

`cancel_run` applies this to every non-terminal job of a run, then decides the run's dependents once. `sentinel admin cancel --job|--run` is the host-local way in; the API (W08) uses the same calls.

## Termination on the worker

`Executor::cancel(attempt)` sets the attempt's cancel flag first, so a step that ends on its own meanwhile is still classified `Canceled` — the desired state wins over the incidental exit status — and then, off the session thread, `podman::terminate_named`:

1. `podman inspect` gives the container's init pid and host cgroup path.
2. **Graceful:** `SIGTERM` to every process in the container's cgroup **except the keepalive** (`cgroup.procs`, read from the host; rootless, so the processes are the worker account's and the signal needs no privilege). The keepalive is spared on purpose: if the container's init died, the runtime would `SIGKILL` everything at once and there would be no grace.
3. Wait up to the grace period (`DEFAULT_CANCEL_GRACE`, 30 s; `Executor::set_cancel_grace`) for the cgroup to empty of step processes.
4. **Forced:** if anything is still there, `podman stop -t 0` and `podman rm -f` — the whole container and process group, not one pid.

Step processes are looked up in the container's cgroup **and every cgroup nested under it** (bounded), where a runtime may place an exec'd step. If nothing could be signalled — an `exec` still starting, a runtime that could not be asked — while the attempt is still running, the cancel is not considered carried out: the next heartbeat's `cancel` tries again, so a cancel is never lost for the rest of a step.

A cancel that lands during preparation ends the attempt as `canceled` too, with its (empty) log closed — and the preparation helpers do not run on: a Git fetch (direct or into the mirror) and a `podman pull` watch the attempt's cancel flag and have their whole process group killed within 50 ms of it, instead of running to their deadlines (10 and 15 min). A pull shared with other attempts (K05) is killed only when its leader's attempt is cancelled, and its followers then pull for themselves rather than inherit a cancellation that was not theirs. Otherwise the step's `exec` returns as the process dies (signal 15, or the script's own exit); the attempt loop sees the flag, records the step `Signaled`/`NotRun` for the rest, finalizes as usual — workspace and container gone, log closed — and reports `Failed(Canceled)`. `Notice::Canceled { forced }` says which way it went.

## Timeouts

- **Execution:** the worker's, per step and bounded by the job's budget ([executor](executor.md#steps-w04)); `ExecutionTimeout`, `timed_out`.
- **Controller backstop:** an attempt still acknowledged past `acked + job.timeout + EXECUTION_GRACE_MS` (10 min) is treated like an expired lease — the worker is renewing but not enforcing, and that is an infrastructure failure, not the repository's.
- **Queue:** a job `queued` for longer than `QUEUE_TIMEOUT_MS` (6 h, server policy) is `QueueTimedOut` → `timed_out`, and its dependents are decided (skipped) in the same transaction. Swept every dispatch pass over the `jobs_queued_since` partial index.

## Lease expiry and capacity release

Every dispatch pass (a wake or the 2 s reconciliation) runs `dispatch::expired`: held attempts whose `lease_until` has passed (over the `attempts_held_by_lease` partial index) plus the execution overruns above. The whole batch is expired in one writer transaction (`expire_batch`), and each lease is re-checked inside it: a renewal that committed after the sweep read the attempt — a worker reconnecting just at its deadline — wins, and the attempt stays held. Each one still due is `expire`d: `LeaseExpired` through the state machine as the controller, the reservation released, the dependents decided. The job ends `infra_failed`. **It is never re-queued on its own**: whether the attempt's side effects happened is unknown, and the plan forbids replaying uncertain work; a rerun is an explicit operator decision. A late report from the expired attempt is refused (the attempt is no longer held), and the worker is told to stop it on its next beat.

On the worker, the lease is measured on the worker's own monotonic clock: a renewal grants `LEASE_MS` (30 s, a worker-protocol constant) from a moment after the heartbeat left, so the worker's deadline is the instant it sent that heartbeat plus 30 s, less `LEASE_GUARD` (5 s) — the controller's wall-clock `lease_until` is never compared with the worker's clock, so no clock skew between the two hosts moves it. Until the first renewal the offer's own lease bounds the work, measured from its arrival. A watchdog thread checks the deadline every second. Once it passes with no renewal — the session was lost longer than the lease — every live attempt is ended, forced, and **nothing is reported**, not even the forced verdict: the controller settles them by expiry, and a report would be stale (or, on a controller that has not expired yet, a cancel nobody asked for). The worker acts before the controller could have expired it, never after. Together with serving a spec only after the acknowledgement is durable (an offer that lapses for a lost ack write never also runs), no two workers can believe they own the same attempt.

A worker that disconnects briefly keeps its work: acknowledged leases run to their deadline, the spool holds the log, and a reconnect within the lease resumes renewing.

## What is not here yet

Reconciliation after a restart is in [reconciliation](reconciliation.md). Concurrency groups and supersession cancellation (cancel the older run of the same PR) are C-tasks that call `cancel_run`. Tenant suspension already cancels through the same desired state ([tenancy](tenancy.md)).

## Verification

`crates/sentinel-store/tests/dispatch.rs`: an unstarted job is `canceled` at once and a second cancel is a no-op; a leased and acknowledged job records the request, stays leased, appears in `cancel_requested` for its worker (not for another), ends `canceled` on the worker's report with capacity released, and cannot be rerun; `cancel_run` touches only the non-terminal jobs. Expiry: not expired while the lease holds or renews; an attempt renewed past its job's timeout plus the grace is expired by the backstop; expiry is `LeaseExpired`/`infra_failed`, releases capacity, skips the dependent, re-queues nothing, refuses the late report, is not found twice, and puts the attempt on the worker's stop list; a plain lapse expires by the deadline alone. Queue timeouts fire at exactly the policy, classify `QueueTimeout`, skip dependents and do not repeat.

`crates/sentinel-store/tests/execution.rs` (Part 04 audit): cancelling an unstarted upstream skips its dependent and the run ends `canceled`; a cancel recorded while an offer is out ends the job `canceled` when the offer lapses or is declined, never parking it in the queue; expiry re-checks the lease so a renewal just before the write wins; a worker `canceled` with no request is `Runtime`. `crates/sentinel-worker/src/process.rs` unit tests: a cancel kills a running helper's group within a fraction of a second. `crates/sentinel-api/tests/api.rs`: cancelling the upstream job over the API leaves the dependent `skipped` and the run `canceled`.

`crates/sentinel-link/tests/link.rs`: a cancel recorded on the controller reaches the connected worker on its next beat while the job stays leased; the worker's `Failed(Canceled)` ends it; a worker that stops cleanly leaves its running job's lease in place.

`crates/sentinel-worker/tests/end_to_end.rs` (as `sentinelbench`, rootless Podman, grace 2 s): `polite` (`sleep 300`) and `stubborn` (`trap "" TERM; while :; do sleep 1; done`) are cancelled after their first output is on the controller; both reach `canceled` in well under the 30 s bound, `polite` gracefully (`forced: false`) and `stubborn` by the forced stop (`forced: true`), their summaries name the cancel and mark later steps `NotRun`, and no container is left in the runtime.
