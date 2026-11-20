# Cloud autoscaling

What an autoscaler would need from Sentinel, and what it must never be allowed to do. **Not built**: this is the written design [the backlog](backlog.md) asked for. Sentinel has no provisioning API today, deliberately — a machine becomes a worker through a one-time enrollment an operator issues ([worker enrollment](worker-enrollment.md)) — and the conclusion here is that the missing pieces are a **demand read** and a **narrow authority to mint enrollments**, not a provisioning subsystem inside the controller.

## What a worker is today, and what only the machine may decide

| Decision | Whose | Consequence for an autoscaler |
|---|---|---|
| The pool, transport, CPU, memory, disk ceilings and priority | The controller's, at enrollment — never the worker's | A scaler proposes an enrollment; it cannot raise a ceiling, and the worker cannot exceed what was approved |
| Architecture, OS, isolation, labels, scratch disk, images | The worker's own statement in its `Profile` at hello | A scaler cannot claim a machine is a microVM host or carries a label. "What a machine can run is the machine's statement, never the controller's guess" |
| Whether the machine can run anything at all | The worker host, which refuses before spending the secret | An autoscaler that boots an unsupported host learns it from a refusal, not from a placement failure |
| Where a job runs | The scheduler, in the transaction that fences the lease | Nothing an autoscaler does places work |

A worker's enrollment is single-use, pool-bound, and expires (`lifetime_ms` defaults to an hour, at most a day). Redeeming it binds the machine's TLS fingerprint and, for Tailcat, its node key. Its identity is immutable: a worker that should serve another pool is revoked and enrolled again, never moved.

## What the scheduler must expose

The queue already explains itself to a human: `dispatch::wait_reason` answers per job with one of `Dependency`, `ConcurrencyLimit`, `ResourceLock`, `Policy`, `ArchMismatch`, `LabelMissing`, `RuntimeMissing`, `NoMatchingWorker` (a CPU/memory shortfall), `DiskShort`, `FairnessHold`, `LocalityWait`, `Capacity`, `Drain`, `WorkerOffline`, or `Ready` ([storage](storage.md#statement-plans)). What an autoscaler needs is the same knowledge **aggregated by the shape of worker that would serve it**, and that read does not exist:

```text
GET /api/v1/admin/demand?pool=NAME
{ pool, shapes: [
    { shape: { arch, os, isolation, labels, cpu_millis, memory_bytes, disk_bytes },
      waiting, oldest_wait_ms, class } ], total, truncated }
```

- **`class` is the whole design.** `unserved` — no enrolled worker states this shape, so new capacity would take the work now. `saturated` — eligible workers exist and hold their capacity, so more capacity helps up to a bound. `unplaceable` — nothing this deployment could boot would run it (a label no image carries, an isolation nobody enables), where scaling is pure waste and the answer belongs in the queue's reason. `held` — dependency, concurrency, policy or cancellation, where capacity changes nothing. **Only `unserved` and `saturated` may ever cause a scale-up.** The distinction is the one thing today's metrics cannot make: `sentinel_jobs_waiting{state}` and `sentinel_jobs_oldest_queued_seconds` tell an operator the queue is long, not whether a machine would shorten it.
- **It must not cost an explanation.** Explaining one page of the queue took 3.7 ms for 5,000 waiting jobs and 20 workers, against 5.9 s to explain every job ([storage](storage.md#statement-plans)), because each explanation probes the fleet. A demand read that reused the explainer per job would be a 5.9-second query behind an autoscaler's polling loop. Two ways to keep it cheap, and the choice is part of the design: read the oldest page of `jobs_waiting` per pool and report `at least` counts, or give the compiled job a small shape key at intake (labels are already normalized and bounded) so the read is a grouped range over the ready index. The second is a migration and a stored shape; the first is honest about being a lower bound. Neither may scan the fleet.
- **The capacity side already exists** and should not be duplicated: `GET /admin/workers?pool` (approved, reported and effective size, reservations, over-cap), `GET /workers?tenant=slug` (free capacity, held attempts), and `GET /admin/placement` (the next round's order with expected finish). An autoscaler reads demand and free capacity; it does not reimplement admission.
- **A demand read is a read.** It needs `platform:admin`, it writes nothing, and it must not become the authority on eligibility — the queue's reason stays the answer to "why is this job waiting", because that is what an operator sees beside it.

## What an autoscaler is allowed to do

One thing: **mint a worker enrollment for one pool**, under a budget, as an audited actor.

- **A scoped authority, not a browser session.** `POST /admin/worker-enrollments` requires a fresh second factor today and a bearer token never steps up, so an unattended scaler cannot use it as it stands. The design is a service principal holding one new scope — `platform:enroll`, bound to a single pool — whose issuance is an operator action on the controller host, like every other credential ([API credentials](api-credentials.md)). The scope is a new bit in a versioned set, so it is an additive [compatibility](compatibility.md) entry and not a schema change by itself.
- **A budget of its own.** Enrollment issuance is limited to a burst of 5 and one per 6 s per administrator today, which is a human's rate. A scaler gets its own ceiling — a count per hour and a floor to the interval — and a refusal is a stop, not something to retry into. Every mint is audited as `worker-enrollment-issued` with the scaler as actor and the reason recorded.
- **The secret never lands anywhere readable.** The enrollment secret is returned once and redeemed once. A scaler delivers it through the channel it already controls (cloud-init user-data, a secret store the machine reads at boot) and never into a log, an argument, a template that persists, or a ticket. The bootstrap script is fetched and checked against `bootstrap_sha256` before it runs, as the web page does.

## What an autoscaler must never do

1. **Place a job, or claim a worker's capability.** Placement is the writer transaction that takes the job's fence and writes the attempt as its reservation. A scaler has no store access and no API to place. Equally, a scaler must not tell the controller what a machine can do: the profile is the machine's statement, and an enrollment's ceilings are the operator's.
2. **Revoke or drain a worker that holds a running attempt without a handoff.** There is no attempt handoff in Sentinel: an attempt runs on the worker it was leased to until it finishes, is canceled, or its lease expires. So scale-down is **drain** (takes no new offers, keeps what it holds, [worker enrollment](worker-enrollment.md#remove-a-machine)) and then **uninstall**, which revokes only once accepted attempts have settled. Revoking mid-attempt is not a scale-down: the store ends the attempt `Reconciled` and the job is lost.
3. **Cancel work to make a scale-down faster.** A cancellation is the tenant's or an operator's decision, never an autoscaler's; the scaler waits, and its deadline is stated in its policy.
4. **Exceed a bound.** Per-shape ceilings set by an operator (a maximum number of hosts for a shape, a minimum floor, a cooldown) are what keep "demand for a shape with no worker" from becoming an unbounded spend. A scaler with no floor can scale to zero the last eligible machine while jobs wait for it.
5. **Reuse or guess identities.** A fresh worker identity, TLS key and node key per machine, generated on that machine; a collision is refused `409` and the enrollment stays unspent. An autoscaler that clones an image with keys baked in produces clones that fight over one identity.
6. **Poll into a rate limit.** The demand read is cheap; the enrollment path is not. A refused enrollment is a back-off, and the deployment's own explain (`Drain`, `WorkerOffline`) is the signal that a worker exists but is not serving.

## Scaling down, and what bounds it

The order is fixed and both sides participate: the controller is told to uninstall (`POST /admin/workers/{wrk}/uninstall`, `202`), the worker drains at once and is revoked when its accepted attempts settle, then the host runs its own uninstall and the machine is destroyed. A scaler that deletes the machine first loses whatever it was running.

What that costs in wall-clock time is stated, not hidden: a job's timeout may be up to 24 hours ([pipeline schema](pipeline-schema.md)), so a scale-down that waits for work to settle can take that long, and a scaler whose deadline is shorter has only two honest options — wait longer, or ask an operator to cancel. A design that promised a fast drain would be promising an attempt handoff that does not exist.

## Failure modes

- **A scaler that scales on the wrong class.** Demand that is `unplaceable` or `held` looks identical to `unserved` in the metrics that exist today. That is the reason the demand read is a prerequisite and not a nicety: without `class`, every autoscaler is guessing.
- **Hosts that never enroll.** A booted machine that fails to redeem burns its enrollment (which expires in an hour) and its budget. The scaler sees enrolments that never became workers, which the enrollment listing reports by state; it must stop, not reissue in a loop.
- **A leaked scaler credential.** Its blast radius is bounded on purpose: one pool, one budget, audited. It cannot read runs, place work, or raise a ceiling.
- **A partition between the scaler and the controller.** Nothing is placed by the scaler, so the only consequence is capacity that does not arrive; the queue's own `sentinel_jobs_oldest_queued_seconds` is what an operator's alert reads.
- **Demand and capacity sampled at different instants.** The scaler's decision is a heuristic over two reads, and it will sometimes add a worker just as the queue drains. A cooldown and a per-shape floor are the mitigation, and a wrong scale-up costs money rather than correctness.

## Constraints from the platform work

- **The enrollment secret is a credential.** It never reaches a log line, an argument, a diagnostic bundle or a template that persists; the routes that issue and redeem it are already bounded for that reason, and a scaler inherits the rule rather than relaxing it.
- **A new scope is a versioned contract.** `platform:enroll` is a new bit with a name, an additive [compatibility](compatibility.md) entry, and a re-read of every stored scope column's bound — the surface already learned this when `artifacts:write` needed migration 73 to be storable.
- **A new route is additive and authorized.** `GET /admin/demand` is a read under `platform:admin`; it writes nothing and adds fields, never changes them.
- **Tenant isolation of capacity.** A scaler bound to one pool can only grow that pool. It must not be able to mint a worker into a tenant's dedicated pool from outside, which is the same rule that refuses a grant on a dedicated pool.
- **A worker's capability is its own statement**, and host ceilings are the controller's approval. Neither moves because an autoscaler asked.

## Before implementation

1. **Measure what a scale-up can even improve.** On the verification hosts, the queue-wait distribution against fleet size for the pilot workloads, so a scale-up policy's target has a number behind it. Without that, the design's first gate would be untestable.
2. **Decide the demand read's shape.** A bounded page of `at least` counts (no migration, honest bounds) or a compiled shape key on the job row (a migration, exact grouped counts, and a new stored fact that placement does not need). The cost evidence is the explainer's page-versus-whole difference above.
3. **Decide the scoped authority.** A `platform:enroll` bit bound to one pool, issued host-locally, is the smallest authority that allows unattended enrollment. Nothing wider is needed and nothing wider should be granted.
4. **Decide the scale-down policy.** The wait it will accept, the floor it will hold, and whether an operator must be the one to cancel work it cannot wait for.

## What this page does not decide

Whether the controller should ever boot machines itself (this design says no: the deployment's own infrastructure does, and Sentinel only says yes or no to an enrollment); which cloud; and whether scale-up may target a microVM-KVM host differently from a Podman host — the shape read would answer that if the demand classes carry OS and isolation, which is why they do.
