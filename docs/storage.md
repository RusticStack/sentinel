# Metadata storage (C02)

`crates/sentinel-store` is the controller's local metadata store: SQLite in WAL mode behind one dedicated writer thread, tenant-scoped row operations, and fenced compare-and-set transitions built on [core contracts](core-contracts.md).

## Bounds and failure behavior

Closed by the Parts 01–02 audit's C02/W02 gate. Every bound is a constant on the crate and every behavior has a wall-clock-asserted test in `crates/sentinel-store/tests/bounds.rs`.

| Resource | Bound | When exceeded |
|---|---|---|
| Read connections | `READER_LIMIT` (8) opened in total, idle ones pooled and reused | A caller waits up to `READ_ADMISSION` (2 s) for a freed reader, then gets `Error::Overloaded` — back-pressure, never a new connection. |
| Writer queue | `WRITER_QUEUE` (256) accepted jobs | `Error::WriterUnavailable` immediately; nothing was attempted. |
| Writer answer | `WRITE_WAIT` (10 s) | `Error::WriteAmbiguous`. The work is still queued or running and **may yet commit**; the store never claims a timed-out write rolled back. Re-read before retrying anything non-idempotent. |
| Panicking closure | caught on the writer thread | Its transaction unwinds and rolls back; the caller gets `Error::WriterPanicked`; the writer keeps serving. |
| Shutdown | `Store::shutdown(timeout)` | `Drained`, or `Stalled` when accepted work outlives the bound. Stalled work is never discarded, and the store then **keeps database ownership** until the process exits rather than inviting a second controller in underneath unfinished writes. |

**One controller owns the database.** `Store::open` takes an advisory OS lock on `<database>.lock` for the life of the store; a second opener — another process, or a misconfigured second controller — gets `Error::AlreadyOwned` at startup instead of a conflict at its first write. The lock is released by the OS on exit, including a crash. SQLite serializing writes is not a multi-controller scheduler design, and this is what enforces that.

## Engine decision

Measured 2026-09-13 with `cargo probe sqlite` and `cargo probe redb` on the same workload (2,000 single-transaction enqueues, a 100,000-row backlog, 2,000 pick-and-lease transactions), WSL2 ext4, two repeats; record in [`bench/c02-engines.jsonl`](../bench/c02-engines.jsonl).

| Engine | Mode | Enqueue commit median / p99 | Dispatch commit median / p99 | Ready pick | Batch insert |
|---|---|---:|---:|---:|---:|
| SQLite 3.53 | `synchronous=FULL` (durable) | 0.50 ms / 1.56 ms | 0.50 ms / 1.41 ms | 2.0 µs | 1.5 M rows/s |
| redb 4.2 | `Durability::Immediate` (durable) | 0.56 ms / 1.13 ms | 0.60 ms / 0.93 ms | 0.8 µs | 1.3 M rows/s |
| SQLite 3.53 | `synchronous=NORMAL` | 5 µs / 17 µs | 6 µs / 21 µs | 0.3 µs | 1.5 M rows/s |
| redb 4.2 | `Durability::None` | 10 µs / 19 µs | 13 µs / 27 µs | 0.2 µs | 1.4 M rows/s |

Both durable paths are bound by the same fsync and land within 20% of each other; redb has a tighter p99, SQLite a lower median and 2x the non-durable throughput. Neither is the bottleneck for a CI controller whose intake is webhooks. The decision therefore rests on what the engine gives for free: SQLite provides declarative constraints (foreign keys, uniqueness, `CHECK`), partial indexes, ad-hoc queries for diagnostics and the web UI, the online backup API, and a file format every operator tool reads. redb would require hand-built secondary indexes and constraint checks in Rust, code that has to be as correct as SQLite's and would not be faster. sled is still alpha and jammdb has had no commits since 2023; neither was benchmarked. **Decision: SQLite via `rusqlite` (bundled), reconsidered only if profiling of a real controller shows the writer thread saturated.**

## Layout and ownership

Migrations are an append-only list of `(version, sql)` in `schema.rs`; each runs in its own `BEGIN IMMEDIATE` transaction and is recorded in `schema_migrations`. Version 1 creates `tenants`, `repos`, `runs`, `jobs` and `attempts` as `WITHOUT ROWID` tables keyed by 16-byte IDs. Version 2 adds `run_specs` (the immutable compiled specification per run: pipeline digest, format byte, postcard blob) and `jobs.spec_index`. Version 3 adds `idempotency_keys`, scoped to (tenant, principal, route): `idempotency::begin` decides execute/replay/mismatch inside the mutation's own transaction and `complete` records the created run, so a duplicate can never execute twice.

Tenant-owned tables carry `tenant_id`; global human users/external identities are linked through memberships. Inserts of runs and jobs are `INSERT … SELECT` from the parent row filtered by tenant; both fail as `NotFound` for a missing or foreign parent. Controller read/transition predicates include `tenant_id`, but these trusted helpers alone do not authorize a user.

Version 4 adds [identity and authorization](authorization.md): namespaces/users/external identities, memberships and explicit repo grants. New grants use composite ownership FKs; triggers enforce equal tenant ownership across the existing parent/child graph even through raw SQL. Migration refuses inconsistent existing rows and unknown newer versions. Client-facing repository and spec queries join current membership/grants and credential scope; authorized dispatch derives the owning tenant inside its writer transaction.

Encodings: IDs are raw UUID bytes; `state_code` is one integer with terminal states at 16 plus the outcome, so the ready-queue partial index is `WHERE state_code = 1` and `>= 16` means finished; `failure_class` uses the core discriminant; timestamps are UTC milliseconds, first entry wins via `COALESCE`.

Version 14 ([worker link](worker-link.md#dispatch-w02)) copies each job's `cpu_millis`/`memory_bytes` from its spec, records a worker's reported capacity, and makes the attempt row the reservation: `cpu_millis`, `memory_bytes`, `offered_ms`, `acked_ms` and `released_ms`, with `attempts_held_by_worker` (partial, `released_ms IS NULL`) for the capacity sum and `attempts_pending_ack` (partial, unacknowledged and held) for the ack-timeout sweep. A trigger fixes an attempt's identity, worker and reservation at the lease and refuses to undo an acknowledgement or a release.

Version 15 ([executor](executor.md#steps-w04)) adds `attempts.summary` (at most 32 KiB, the worker's encoded `AttemptSummary`), written once with the terminal report; the recreated `attempt_update` trigger refuses to replace it.

Version 16 ([cancellation](cancellation.md)) copies each job's execution timeout to `jobs.timeout_ms` for the controller's backstop and adds `attempts_held_by_lease` and `jobs_queued_since`, the partial indexes the expiry and queue-timeout sweeps walk.

## Writer and acknowledgement policy

One thread owns the only write connection. `Writer::write` sends a closure over a bounded channel (256 slots), runs it inside `BEGIN IMMEDIATE`, commits, and only then replies. With `synchronous=FULL` the WAL is fsynced before `COMMIT` returns, so **a write is acknowledged to the caller only when it is on disk**. This is the contract worker acknowledgements, lease grants and cancel requests rely on. `Durability::Normal` exists for replayable data and tests; it is never used for transitions.

A full queue returns `WriterUnavailable` immediately instead of blocking or growing; callers shed load or retry with back-off. Readers use separate read-only WAL connections and observe a committed snapshot. The current connection pool has no hard limit, writer result waits/shutdown joins have no deadline, and long read snapshots can constrain checkpoint progress. These are [open integration gates](parts-01-02-audit.md), not bounded-production-service claims.

## Transitions

`jobs::transition` reads the row, lets `JobControl::apply` decide (actor permission, fence, edge), then executes one static `UPDATE … WHERE id=? AND tenant_id=? AND state_code=? AND fence=?`. Zero rows changed means the row moved between read and write: `Conflict`, and the transaction rolls back. `jobs::lease` bumps the fence, transitions to `Leased` and inserts the attempt row in the same transaction. `jobs::pick_ready` is a single indexed `ORDER BY priority, created_seq LIMIT 1`; the test asserts the query plan uses `jobs_ready`. `jobs::run_state` recomputes the run outcome from job rows through the core aggregation. `runs::create_run` writes the run, its spec and its job rows in one transaction (dependency-free jobs start `Queued`); `runs::rerun_job` applies the core `Rerun` edge with a compare-and-set that clears attempt history and keeps the fence.

## Verification

Thirteen integration tests. Runs: spec persisted and read back byte-for-byte, job states seeded from dependencies, cross-tenant read denied, duplicate run creation rejected with the original intact, rerun keeps the fence and stales the old attempt, rerun refused for running and cancelled jobs. Core: migrations idempotent with WAL and foreign keys on; full lifecycle with fence, timestamps and run aggregation; stale fence and wrong tenant rejected; compare-and-set conflict rolls back the whole transaction; dangling and cross-tenant inserts fail; ready-queue ordering and index use; durable cancel flag; acknowledged writes survive drop-without-checkpoint and reopen; writer back-pressure rejects only overflow. Plus two codec round-trip tests. All pass on Windows and Linux.

Not yet covered: crash injection mid-fsync (requires a fault-injecting VFS), multi-process access (unsupported by design), and checkpoint scheduling under sustained load.
