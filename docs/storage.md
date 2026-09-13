# Metadata storage (C02)

`crates/sentinel-store` is the controller's local metadata store: SQLite in WAL mode behind one dedicated writer thread, tenant-scoped row operations, and fenced compare-and-set transitions built on [core contracts](core-contracts.md).

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

Migrations are an append-only list of `(version, sql)` in `schema.rs`; each runs in its own `BEGIN IMMEDIATE` transaction and is recorded in `schema_migrations`. Version 1 creates `tenants`, `repos`, `runs`, `jobs` and `attempts` as `WITHOUT ROWID` tables keyed by 16-byte IDs.

Every table after `tenants` carries `tenant_id`. Inserts of runs and jobs are `INSERT … SELECT` from the parent row filtered by tenant, so a run cannot reference another tenant's repo and a job cannot reference another tenant's run; both fail as `NotFound`, the same answer a nonexistent row gets. Every read and transition predicate includes `tenant_id`. Foreign keys are enforced (`PRAGMA foreign_keys=ON`) as a second line of defence.

Encodings: IDs are raw UUID bytes; `state_code` is one integer with terminal states at 16 plus the outcome, so the ready-queue partial index is `WHERE state_code = 1` and `>= 16` means finished; `failure_class` uses the core discriminant; timestamps are UTC milliseconds, first entry wins via `COALESCE`.

## Writer and acknowledgement policy

One thread owns the only write connection. `Writer::write` sends a closure over a bounded channel (256 slots), runs it inside `BEGIN IMMEDIATE`, commits, and only then replies. With `synchronous=FULL` the WAL is fsynced before `COMMIT` returns, so **a write is acknowledged to the caller only when it is on disk**. This is the contract worker acknowledgements, lease grants and cancel requests rely on. `Durability::Normal` exists for replayable data and tests; it is never used for transitions.

A full queue returns `WriterUnavailable` immediately instead of blocking or growing; callers shed load or retry with back-off. Readers use separate read-only connections from a small pool; in WAL mode they never block the writer and always see the last committed state.

## Transitions

`jobs::transition` reads the row, lets `JobControl::apply` decide (actor permission, fence, edge), then executes one static `UPDATE … WHERE id=? AND tenant_id=? AND state_code=? AND fence=?`. Zero rows changed means the row moved between read and write: `Conflict`, and the transaction rolls back. `jobs::lease` bumps the fence, transitions to `Leased` and inserts the attempt row in the same transaction. `jobs::pick_ready` is a single indexed `ORDER BY priority, created_seq LIMIT 1`; the test asserts the query plan uses `jobs_ready`. `jobs::run_state` recomputes the run outcome from job rows through the core aggregation.

## Verification

Nine integration tests: migrations idempotent with WAL and foreign keys on; full lifecycle with fence, timestamps and run aggregation; stale fence and wrong tenant rejected; compare-and-set conflict rolls back the whole transaction; dangling and cross-tenant inserts fail; ready-queue ordering and index use; durable cancel flag; acknowledged writes survive drop-without-checkpoint and reopen; writer back-pressure rejects only overflow. Plus two codec round-trip tests. All pass on Windows and Linux.

Not yet covered: crash injection mid-fsync (requires a fault-injecting VFS), multi-process access (unsupported by design), and checkpoint scheduling under sustained load.
