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

## Objects and manifests (D01)

`sentinel-store::objects` is the controller's content-addressed body store, under the same data directory as the database:

```text
<data>/objects/<tenant>/<hex[0..2]>/<hex-digest>        committed objects
<data>/manifests/<tenant>/<kind>/<name-hash>/<version>  manifest files
<data>/tmp/<unique>                                     staging, never committed
```

Objects are addressed by their BLAKE3-256 digest and deduplicated **within one tenant only** — identical bytes stored by two tenants are two objects, so object existence never leaks across tenant boundaries. A reference commit is the `objects` row (migration 23): `stage` streams the body to `tmp/` hashing in one pass, verifies any declared length/digest and the caller's byte cap, `fdatasync`s the file, atomically renames it into the tenant's namespace and `fsync`s the directory chain; `commit` then inserts the row inside the caller's transaction. A crash between rename and commit leaves an **orphan** — wasted space, never a published incomplete object. The triggers on both tables refuse `UPDATE` and `DELETE`: reference removal is the reclamation stage (D06+), not a write path.

Manifests are named, monotonically versioned lists of object references (`kind`, `name`, `version` → immutable file + row). `commit_manifest` chooses `MAX(version)+1` inside the transaction, **refuses references to objects the tenant has not committed**, writes the manifest through the same stage discipline and inserts the row — a manifest can never dangle. Entry paths are `/`-separated relative archive names; `.`/`..`, absolute, drive-prefixed and separator-bearing components are refused at commit. The row records the manifest file's own digest and the summed payload length for quota and retention accounting without reopening the file.

Reads are verified: `read` streams the object while rehashing and compares digest *and* length to the committed row; `manifest` parses the file and checks it against its committed digest and identity. A committed row whose file is absent or short is `Corrupt`, not `NotFound`.

**Recovery.** The server opens the store and runs `recover` at startup (logged as `objects_recovered`); `sentinel admin objects recover` runs the same reconciliation host-locally while the controller is stopped. It removes anything in `tmp/` (incomplete staged writes), then walks both trees against the committed rows: files with no row are **orphans** (reported, never deleted — a staged-but-uncommitted file and a leaked file are indistinguishable), files whose row disagrees on length are **corrupt**, and rows with no file are **missing**. `verify` — `sentinel admin objects verify` — rehashes every committed object for the deeper integrity check that catches content rot a length check cannot see; it is a drill, not a per-request cost.

## Resumable uploads, reads and materialization (D02)

`<data>/incoming/<upl_…>` is durable staging for resumable upload sessions, backed by the `uploads` table (migration 24): each row records the owning tenant, declared length, an optional declared digest, a compact blob of received byte ranges, an expiry and a state (`open` → `committed`/`aborted`).

- `begin_upload` creates the row and a file pre-sized to the declared length in one transaction. `put_chunk` writes a chunk at a client-chosen offset — bytes are `fdatasync`ed **before** the range is recorded, so a crash can never claim bytes it does not hold — and overlapping or identical re-sends merge into the range set, making retries idempotent without corrupting the count. `upload` reports the sorted disjoint ranges so a resuming client sends exactly what is missing. Chunks outside the declared length, sessions past their TTL (≤ 24 h), and any write to a sealed or aborted session are refused; touching an expired session retires it.
- `seal_upload` requires the ranges to tile `[0, len)`, rehashes the staged bytes and checks them against the declared digest, then renames the file into `objects/<tenant>/…` and commits the reference inside the caller's transaction — the D01 publish order is preserved, so a crash can orphan but never publish a partial object. Sealing twice answers the same digest; a digest mismatch keeps the session open so the client can rewrite whichever ranges were wrong.
- `sweep_uploads` retires expired sessions and drops their files; it runs at server startup and as `sentinel admin objects sweep`. `recover` keeps files that still have an open row and sweeps the rest.

Downloads go through `open_read`, which registers a live `Reader` per `(tenant, digest)` and hands out a seekable handle; the registration drops with the guard, and `reader_active` is how reclamation (D06) will refuse to unlink a file still being streamed. `materialize` writes a manifest's entries into a directory: entry paths are re-validated, every ancestor component under the destination is checked for symlinks, existing targets are refused, and object bytes are verified while streaming — an extract cannot escape its destination even if the directory was prepared by an adversary.

The API exposes this as `POST /tenants/{slug}/uploads`, `GET|PUT|DELETE /uploads/{upl}` (`PUT` takes `?offset=` and a raw body of at most 8 MiB), `POST /uploads/{upl}/commit` and `GET /tenants/{slug}/objects/{digest}` with `Range: bytes=…` support. Upload sessions require operator-level tenant membership; downloads require membership. An upload id resolves its owner before authorization so a foreign id is indistinguishable from a missing one. At most four transfer bodies are in flight at once (`TRANSFERS`); the next request is `rate_limited` rather than queued work.

## Artifact records (D03)

The `artifacts` table (migration 25) is the durable outcome of each declared artifact on an attempt: one row per `(attempt_id, name)` with the job and run for scoping, a terminal `state_code` (`captured`, `absent`, `failed`), entry and byte counts, the `manifests` version when captured, the retention deadline and the creation timestamp. `UNIQUE(attempt_id, name)` makes a redelivery a conflict rather than a duplicate; the state/identity columns sit behind the usual immutability triggers.

A captured row and its manifest commit in **one writer transaction**: the controller stages each file body through `stage_begin`/`stage_write`/`stage_seal` (the streaming counterpart of `stage` — a `Staged` keeps the same rename-then-commit discipline and refuses to discard a file another committer won), commits the object references, commits the `{job_id}/{name}` manifest under `Kind::Artifact`, then inserts the artifact row. Absent and failed outcomes write only the row. A partial publication that never reaches `ArtifactEnd` leaves staged files that `recover` sweeps and in-flight byte accounting that the session drop releases; no artifact row exists for it, so nothing claims it.

The API lists a run's artifacts (`GET /runs/{run}/artifacts`) and shows one row's detail (`GET /runs/{run}/artifacts/{arf}`), the latter inlining the manifest's entry paths, digests, lengths and modes; entry bytes download through the existing `GET /tenants/{slug}/objects/{digest}` route.

## Segmented logs (D04)

Attempt logs no longer live in one flat `logs/<attempt>.log` file. Each attempt owns `logs/<run>/<job>/<attempt>/`: `seg-NNNNNN` record segments sealed at 4 MiB and compressed to `seg-NNNNNN.z` (zlib, `SNLZ` format 1) by a background thread, a sparse `index` (`SNLI` format 1; 41-byte checkpoints on segment starts, step changes, every 64 frames, and a seal record per closed segment), and the atomic `end` marker (`SNLE` format 1) that is the single completeness boundary. Sequence jumps record holes instead of refusing; fills narrow them; the marker's gap list merges observed holes, worker-declared gaps and the never-stored tail (≤ 1,024 ranges, coalesced). Reopen truncates torn segment and index tails, rebuilds a missing index, repairs an end record that reached a segment without its marker, and re-queues un-compressed sealed segments. Reads seek by sequence through the index and can filter to one step; pre-D04 flat files still read through `read_tail`. The full contract is in [logs](logs.md#on-the-controller-segments-index-and-the-end-marker-d04).

## Terminal publication (D05)

A job's terminal transition now carries its data status in the same transaction — `finish` is also the finalization boundary:

- **`attempts.log_state`** (migration 26) records the log's durable status: `pending` while live, `complete` once the `end` marker is on disk, `incomplete` when the job went terminal first. The `LogEnd` handler writes the marker, then the row, and only then answers `Acked`/`LogEndAck`; the writer-transaction commit means an acknowledgement is never sent for a status that is not durable. The recreated `attempt_update` trigger adds `NEW.log_state < OLD.log_state` to the forbidden moves — the column may heal `incomplete → complete` on a late retransmitted end, never regress.
- **Artifact coverage is checked against the stored run spec**, not the worker's claim: for every declaration due under the outcome (`when`), a row must exist, and a *required* one must be `captured`. Due-but-missing declarations get `failed` rows so the loss is on record; a reported `Passed` standing over an uncaptured required artifact is applied as `Failed(Publication)` instead. Optional misses and not-due declarations change nothing but the row set.
- The same stamping runs on every terminal path — `report`, `expire`, `abandon`, `reconcile_startup` — all take the `LogStore` so the answer to "was the end marker durable at publication" is the marker itself, not a worker's claim. A caller without a log store (`None`) answers `incomplete`, never `complete`.

Because log frames and `LogEnd` are accepted for an attempt the worker owns even after release (`attempt_log_scope`), a post-terminal retransmission can still land its marker and upgrade `incomplete → complete`; artifact publication stays held-only, since it is part of the verdict.

## Disk admission, quotas and reclamation (D06)

One `Admission` gate (`sentinel_store::space`) watches the filesystem holding the data directory — `statvfs` on Unix, `GetDiskFreeSpaceExW` on Windows — with the probe result cached for one second. The model is a single axis of free bytes: `reserve` is held back for the metadata database and log evidence, `low`/`high` are the close/reopen hysteresis for discretionary admission, and `floor` (inside the reserve) is where even log frames refuse. Between probes the in-flight charge is what keeps concurrent writers honest: `admit` charges promised-but-uncommitted bytes per tenant and per filesystem, released when the bytes land (the next probe sees them) or the write is abandoned. A refused frame is reported `StorageFull`, never silently dropped and never recorded as a log hole.

Object staging and streaming artifact writes charge per write; resumable uploads charge only the byte ranges each chunk actually adds (re-sent ranges are free), with the charge released on seal, abort, expiry or a failed write. `begin_upload` also checks the tenant's quota against `tenant_usage` — committed object bytes plus open uploads' declared lengths, kept by triggers — before promising the reservation, and `commit` re-checks it for staged objects. Both surface as `QuotaExceeded` (`quota_exceeded`, 403) or `StorageFull` (`storage_full`, 507, retryable) through the API. `tenant_quotas` rows are the per-tenant override of the configured default; `admin tenant quota --tenant SLUG [--bytes N | --clear]` manages them host-locally.

Reclamation is now real but stays reader/lease-safe (migration 27): `manifest_refs` records the object→manifest edge at commit and is backfilled for pre-D06 manifests by `index_refs` (`manifests.refs_indexed` marks the flag's one-way flip, the only manifest update the recreated trigger admits). A tenant with any unindexed manifest is exempt from reclaim — an unseen reference must never be collected under it. `reclaim` deletes an object row only when no edge remains, no unexpired `object_leases` row pins it (`lease`/`release_lease`/`sweep_leases`), no live `Reader` streams it, and it is older than a 24-hour unreferenced grace; the caller unlinks the returned paths after commit, and `sweep_orphans` removes files no row owns once their mtime passes a one-hour grace. `artifacts.retain_until_ms` (D03) is the artifact retention deadline `sweep_expired` acts on: the row and its manifest version retire in one transaction, cascading the edges that then let `reclaim` collect the objects.

The controller runs the whole pass — expired uploads and leases, artifact retirement, the reference backfill, object reclaim, orphan files, and logs older than `log_retention` — on the dispatch loop's wake, at most every `sweep_interval` ([configuration](configuration.md)). Below the low watermark the dispatcher also stops placing new work and artifact grants answer `TooLarge` — a job that cannot store its output does not consume capacity finding out. `admin objects reclaim` runs the same pass by hand against a stopped server and `admin objects status` reports free space and per-tenant usage.

## Fault boundaries (D07)

Every write path settles one of two ways: bytes durable *and* row committed, or the residue found and swept. `tests/faults.rs` drives the boundaries — a `commit` or `commit_manifest` rolled back after the rename leaves an orphan that `recover` reports and `sweep_orphans` collects past the grace; an upload chunk whose transaction rolled back leaves bytes the resend converges into a verifiable seal; closed admission refuses object bytes while log frames still flow above `floor`; binary frames round-trip byte-identical, oversized frames refuse and the refused sequence becomes a declared gap; the per-attempt log cap refuses with `log size` and the refusal is declared, not silent; a torn segment tail never reaches a tail reader and is cut on reopen; and a lost `end` marker is rebuilt from the sealed segment's end record instead of silently reopening the log. `read_tail` now streams flat logs in bounded chunks instead of loading the whole file.

## Verification

Thirteen integration tests. Runs: spec persisted and read back byte-for-byte, job states seeded from dependencies, cross-tenant read denied, duplicate run creation rejected with the original intact, rerun keeps the fence and stales the old attempt, rerun refused for running and cancelled jobs. Core: migrations idempotent with WAL and foreign keys on; full lifecycle with fence, timestamps and run aggregation; stale fence and wrong tenant rejected; compare-and-set conflict rolls back the whole transaction; dangling and cross-tenant inserts fail; ready-queue ordering and index use; durable cancel flag; acknowledged writes survive drop-without-checkpoint and reopen; writer back-pressure rejects only overflow. Plus two codec round-trip tests. All pass on Windows and Linux.

Not yet covered: crash injection mid-fsync (requires a fault-injecting VFS), multi-process access (unsupported by design), and checkpoint scheduling under sustained load.
