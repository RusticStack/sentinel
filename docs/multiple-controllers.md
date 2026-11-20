# Multiple active controllers

What it would take for two controllers to serve one deployment. **Not built and not scheduled**: this page is the written design [the backlog](backlog.md) asked for, and its conclusion is that the current shape does not justify a second active controller — the constraints that make one controller correct are the same ones that would have to be rebuilt, and the pressure such a change answers has not been measured here. It states the two candidate designs, picks between them on the evidence that exists, and names what would reopen the question.

The binding constraint is not the scheduler's throughput. It is that the metadata store is announced, and enforced, as owning exactly one controller: `Store::open` takes an advisory lock on `<database>.lock` and a second opener gets `Error::AlreadyOwned` at startup rather than a conflict at its first write ([storage](storage.md#bounds-and-failure-behavior)). Everything else in this page follows from that fact and from the two things that are process-local rather than stored.

## What is authoritative today, and where it lives

| Fact | Where it lives | Why a second controller cannot just read it |
|---|---|---|
| Which jobs are ready, leased or finished | `jobs.state_code`, `jobs.fence`, the attempt row as the reservation (migration 14) | Shared already: it is rows, and every transition is a compare-and-set on state and fence. This is the part that would survive |
| Which workers are connected | An in-process map (`sentinel-link::controller`, `connected()`), not a column. `workers` stores `last_seen_ms` and nothing about transport state | A second controller sees an empty fleet. Placement is handed the connected set (`dispatch::place_in_fleet`) and offers travel only on the session that holds the worker, so a job leased by a controller that does not hold that worker's session can never reach it |
| That a commit needs dispatch | `Changes` — a generation counter and a condition variable — in `crates/sentinel-store/src/lib.rs`, so "a commit happened" is a fact only this process knows | Another process's commits raise no wake. A second controller would dispatch on its own pass or its own reconciliation interval, which is a latency change, not a correctness one |
| Mutually exclusive resources and worker capacity | `resource_locks` and the `attempts_held_*` partial indexes | Rows, and consistent within one database. They stop being consistent the moment two controllers compute a total from different snapshots |
| The controller's link identity | `controller.crt` / `controller.key` in the data directory, carried by [backup](backup.md) | Two hosts answering one address need the same key, which means a private key on two machines |
| Attempt logs, objects, backups | Paths under the data directory | A takeover has to leave the new controller able to read the files the old one wrote |

**A shared database file is not one of the options.** SQLite in WAL mode requires every process using the database to be on the same host as the file — the write-ahead log is coordinated through a shared-memory index the processes map together — and Sentinel runs WAL ([storage](storage.md)). The store's lock is an advisory lock on a local filesystem, released by the OS on exit including a crash, and a filesystem that does not support it makes `Store::open` fail with `Error::Io` rather than run unlocked. So "two controllers on two hosts, one `metadata.sqlite` on a shared volume" fails on three independent counts: the lock is not a distributed lease, SQLite does not support the mode, and the invariants below are single-transaction invariants that a lagging copy would silently violate.

What those invariants are, specifically: the quota check runs inside the writer transaction that commits an artifact ([retention](retention.md)); `idempotency::begin` decides execute-or-replay inside the mutation it guards; placement reads candidates, worker capacity and resource locks and writes the lease in one transaction; the second-factor and session rules make their decisions in the closure that writes the effect. There is no compensating path for any of them. A design for two active controllers therefore cannot mean "two writers on one database"; it can only mean **one writer at a time** (Design A) or **one writer per disjoint set of rows** (Design B).

## Design A — one database, one writer, failover by a fenced leader lease

This is the availability half of the question, and it is the only one that keeps every invariant above. One controller owns the database at a time, and a standby opens nothing until the leader's lease has expired and the database and its files are reachable.

What would have to change:

1. **The ownership check becomes a lease.** `Store::open`'s lock is a file lock, which is exactly right for "one process on this host" and useless for "one controller out of two hosts". The lease would be a row (holder, generation, deadline) plus a renewal, with the same property the store already insists on: the *writer* refuses a write whose generation is stale, so a leader that paused past its deadline cannot commit after the standby took over. The ownership check today fails closed; a lease must fail closed the same way — a standby that cannot reach the lease is not a standby.
2. **A durable fleet registry.** `workers` gains what a takeover needs to know: which identities were connected, on what transport, holding what. The reconciliation this enables already exists in outline — `dispatch::expire` re-checks the deadline in its own transaction, `reconcile_startup` settles what a restart finds, and the worker redials with its identity when the controller returns ([reconciliation](reconciliation.md), [resilience](resilience.md)) — so the takeover path is "expire what the old leader held and let the workers reconnect", not "know their state exactly". Forgetting a worker is safe; remembering one wrongly is not.
3. **One identity, two hosts, one at a time.** The new leader must present the fingerprint the workers pinned, so the controller key lives on both machines or in a small sealed share. That is a stated security cost, not an implementation detail: it turns "steal one host" into "steal two".
4. **Files follow the database.** Objects, attempt logs and backup targets have to be on storage the new host can read, and the backup scheduler's `DIR/.lock` serialization ([backup](backup.md)) assumes one writer of the backup directory, which the lease has to cover too.
5. **A takeover pass, not a merge.** The standby must not resume mid-run work; it expires, reconciles and lets workers dial back in. That is exactly the path the failure drills already exercise for a killed controller ([resilience](resilience.md)).

Failure modes:

- **A slow leader, not a dead one.** If renewal pauses past the deadline the standby takes over while the first process still believes it leads. The fence on the write is the only thing that saves this; without it both would place. With it, the old leader's writes fail and it exits, which is the correct outcome and a visible one.
- **Placement under a stale view.** During the handover an attempt may be expired while its worker is still running it. Today's rule already covers the consequence: the worker's renewal is refused and the attempt ends `infra_failed`, and a worker with a stale attempt is told to stop ([worker link](worker-link.md)). It is a lost job, not a corrupt one, and that is the trade a failover makes.
- **A split backup directory.** Two hosts appending to one backup target is the failure `backup`'s lock exists to prevent; the lease must be the same authority.
- **It is still not HA of the data.** The database is a single file on one host; "failover" here means minutes, not seconds, and RPO is whatever the newest backup is (the measured objective is one hour, [backup](backup.md#recovery-objectives)).

## Design B — tenant-sharded, multi-active

The only shape in which two controllers are genuinely active at once without a shared database: each tenant's rows live in a database file owned by exactly one controller, and a deployment-wide control database owns the facts that are not a tenant's — pools, worker identities, enrollment, host policy, and which controller owns which worker's session.

What would have to change:

1. **A control database, owned by one controller.** It is still a single writer, but it holds only the small, slowly moving tables: tenants and their shard assignment, pools and grants, workers and their policy, quotas. Losing it is losing the fleet map, not the deployment's runs.
2. **Worker reservations move out of the shards.** This is the hard part. Today a worker's free capacity is a sum over `attempts_held_by_worker` in the same transaction that places ([storage](storage.md#statement-plans)). With tenants in different databases, two shards would each compute a total from their own rows and over-commit one machine. So the reservation has to live where the fleet map lives, and placement becomes two phases: reserve in the control database, lease in the shard, release the reservation if the lease fails. That is a distributed transaction by another name, and it needs a new class of stuck reservation and its own sweep.
3. **A worker is owned by one controller.** A worker dials one address and its session lives in one process, so only that controller can offer to it — and that controller must be the one holding the tenant's shard, or the offer has nowhere to write its lease. Assigning workers to shards is therefore a placement constraint of its own, with the pathological case of a worker that serves several tenants on different controllers. Either those tenants place only when the worker is free (and the worker is re-homed), or the offer path grows a forward between controllers.
4. **Cross-tenant reads fan out.** The platform tenant list, per-tenant storage usage, the diagnostics bundle, retention and quota passes that walk every tenant ([retention](retention.md)) become N reads with N failure modes and no single consistent snapshot. Each one needs a stated staleness rule, because a page that sums across shards can no longer promise the transaction it promises today.
5. **Lanes need an owner.** Schedule, checks outbox, mail outbox, replicator, AI poll and worker sweeps are one loop each today because there is one controller. With several, every lane needs a "who runs this pass" decision. Some are already row-safe — a schedule occurrence is a row keyed by its instant, so a second controller computing the same instant fires one run ([schedules](schedules.md)), and a checks publication is claimed by a compare-and-set on `(id, seq)` — but "two drainers are harmless" is a per-lane statement nobody has proven for all of them.

Failure modes:

- **A partition between two controllers** is now a partition between two *writers*: each keeps placing on its own workers for its own tenants, and the fleet map they share goes stale in both directions. The safe behaviour is to place only what the controller can see (its own sessions), which is what it would do — but a worker re-homed across the partition would take offers from neither until it re-dials.
- **A shard that cannot be reached.** The control database knows the shard exists; the controller that owns it is down. There is no failover of a shard unless each shard also has Design A, so this composes into A plus B rather than replacing A.
- **Stranded reservations.** The two-phase placement's whole failure surface: a reservation with no lease, a lease with no reservation, and the sweep that must be able to tell them apart without guessing.

## Constraints from the platform work

Whatever the design becomes, these hold, because they are the boundaries the rest of the system is built on:

- **Separate controller and worker processes.** Nothing is placed in-process; an offer exists only on a session.
- **Tenant ownership on every row.** A sharded design keeps the `tenant_id` predicate on each table, and a cross-tenant read stays a fan-out rather than a join across shards.
- **Durable transitions with fences.** A lease is a compare-and-set on job state and fence. No design here may write a job's state as a side effect of a coordination decision.
- **Bounded resources.** The writer queue (256 jobs), the read admission (2 s) and `WRITE_WAIT` (10 s) are the store's declared bounds; a lease, a registry or a two-phase reservation each adds a bound of its own that has to be named ([storage](storage.md#bounds-and-failure-behavior)).
- **Versioned surfaces.** A worker told to dial another controller, or to re-home its session, is a worker-protocol change under [compatibility](compatibility.md), raised a release before it is required. A registry or lease table is a contiguous migration.
- **Diagnostics stay sanitized.** A lease or registry row names holders and generations, never addresses or key material.

## What I would pick, and what would justify it

Neither, today — and the reason is not engineering conservatism. The engine decision that chose SQLite says in as many words that the writer is not the bottleneck for a webhook-fed controller and that it is "reconsidered only if profiling of a real controller shows the writer thread saturated" ([storage](storage.md#engine-decision)); no such profile exists in `bench/`, and the dispatch path places from indexes over a page of candidates rather than from a scan ([intake](intake.md#demand-provisioning-and-reconciliation)). Nothing here has measured a controller whose writer, session count, or offer loop is the constraint a second active controller would relieve. Building B first would pay for a distributed placement design to solve an unmeasured problem, and buy a class of bug — stale capacity totals across shards — that today cannot exist.

**What I would do instead, and what it costs.** Design A's prerequisites are worth having on their own, because they are also what makes a takeover quick: a durable statement of which workers were connected, and a leash on the backup directory's writer. Both are small and both are useful to the restart path that exists. A failover controller is then an operational choice for a deployment with an availability requirement, not a new scheduling model.

What would justify revisiting this page:

- **A measured controller ceiling.** A recorded number showing dispatch latency or offer throughput degrading while one controller serves every worker session — for example, placement rounds whose transaction waits behind the writer at a fleet size we can name. The measurement is the gate; this page is not evidence of it.
- **An availability requirement shorter than restore.** Today's documented objective is RPO ≤ 1 hour and RTO ≤ 15 minutes for up to 100 GiB ([backup](backup.md#recovery-objectives)). A deployment that needs minutes, rather than quarter-hours, is asking for Design A.
- **A deployment whose tenants must live in separate failure or trust domains** — a shard per customer rather than a row filter. That is the case where Design B's cost is the requirement rather than an optimisation, and where the fan-out reads are acceptable because the operator wants the boundary.

## Before implementation

1. **Measure the ceiling.** A fleet-load and session-load record on `kvm-host` at the size where one controller's placement or link path stops meeting its budget, with the queue's own wait reasons beside it. Without it, the design has no problem statement.
2. **Decide whether the controller key may live on two hosts.** A sealed share, an HSM, or a documented exception with step-up on activation — an owner decision, because it weakens the property that a worker's pin is one machine's identity.
3. **Decide what the fleet registry is allowed to claim.** A row that says "connected" can be wrong; the design must state what the new leader does with a claim it cannot verify, and the answer this page proposes is "expire it and let the worker redial".
4. **Prove the fence refuses a stale leader's write,** with a test in the shape of the existing refused-write suites, before any failover is exercised.

## What this page does not decide

Whether the store should ever leave SQLite; whether the controller should split into an API tier and a dispatch tier (a stateless front-end forwarding writes to the owner buys HTTP capacity and no write capacity, and is not "multiple active controllers"); and whether a deployment may run several *independent* controls — one per pool — which is what the runner-mode and multi-host work already makes possible without any of the above.
