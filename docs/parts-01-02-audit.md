# Parts 01–02: high-level audit

Reviewed 2026-09-14 before A01, then updated with its ownership fixes. This is an architecture/contract and evidence review, not a line-by-line security audit or production qualification. Reviewed the tracker, benchmark records/guides, runtime boundaries, core IDs/state machine, store/schema/query paths, protocol contracts, pipeline compilation/run specs/hash resolver and existing failure tests. The pre-change Windows `cargo test-cli` suite passed.

## Assessment

**The foundations are useful enough to proceed with identity and authorization. They are not yet a qualified execution engine.** Parts 01–02 have real code and tests, including SQLite crash/reopen and malformed-parser coverage. C06 was reopened for its filesystem resolver and subsequently closed by the hardening described below. The remaining integration gates should be closed before accepting executable work.

### Part 01 — foundation and measurement

- Separate Linux server/worker lifecycles, portable CLI, feature gates, toolchain/lockfile and contributor commands are in place. The lifecycle remains explicit about what it implements.
- F04 has actual monotonic lifecycle measurements, propagated IDs, bounded work/diagnostic queues and failure tests. Lossy diagnostics are correctly distinguished from future durable job logs.
- F05/F07 records identify WSL2, runtime, resource configuration and filesystem. They support development choices, not production p95 claims. SQLite and clone probes test narrower workloads than a full scheduler/cache service.
- F06 identifies the shared VPS behind the runner labels, cgroup contention and wait-heavy tests. Cached compilation alone cannot explain away a 193-second race-test package. The guide records the unprofiled Docker/integration work and unmeasured live-CI contention case.
- Tailcat's non-reconnecting forwarder is recorded as a failure, with real-network/self-hosted-relay qualification still outstanding. No new remote/VPS probes were run during this audit.

### Part 02 — contracts and persistence

- Typed inline IDs, fenced transitions and run aggregation have useful behavior coverage. API errors, cursor tenant binding, limits and protocol negotiation are concrete contracts.
- Strict YAML parsing and deterministic compilation have fixture, truncation and mutation coverage. Offline explain correctly leaves runtime credentials/hashes unresolved.
- The SQLite writer acknowledges after transaction commit; rollback, conflicting leases, idempotent dispatch and real process-abort/reopen have tests. These do not prove power-loss behavior or bounded response time under stalled storage.

## Findings and disposition

| Priority | Finding | Evidence / consequence | Disposition and verification gate |
|---|---|---|---|
| High | Database ownership depended on using the right helper | `schema.rs` migrations 1–3 had independent tenant and parent foreign keys. Raw SQL could insert a run in tenant B referencing tenant A's repo, despite `jobs::insert_run` rejecting that through its own predicate. | **Fixed in A01 migration 4.** New grants use composite ownership FKs; triggers protect the existing run/job/attempt/spec/idempotency graph and immutable parent ownership. Migration refuses inconsistent existing rows. Tests cover raw-SQL attacks, rollback and v3 upgrade. |
| High | Tenant filtering was not user authorization | Existing `jobs`/`runs` take a tenant ID and trust their internal caller. Choosing another tenant is not an authenticated permission check. | **Addressed by A01's client-boundary APIs.** Live joined repository queries and authorized dispatch/spec reads derive ownership from stored rows. Raw store/controller primitives remain trusted internals; W08 must use the authorized boundary. |
| High | `hash_files` lacked hostile-filesystem bounds | Original resolver collected entire directories, had no visited-entry/depth budget, trusted initial lengths while reading to EOF, and separated symlink checks from path opens. | **Fixed in C06 follow-up.** [Streaming traversal, work/depth/path/unique-file/actual-byte budgets and Linux descriptor-rooted opens](hash-files.md), with eight Linux resolver tests including replacement and failure paths. Snapshot consistency remains the documented W03 private-workspace lifecycle responsibility. |
| Medium | Store resource bounds lag the F04 executors | `Store::read` opens another connection whenever its pool is empty and retains every returned connection. `Writer::raw` waits indefinitely, `Writer::drop` joins indefinitely, and a panicking closure terminates the writer thread. | **Open C02/W02 integration gate.** Bound readers/admission and define writer failure/drain behavior without claiming that a timed-out write was rolled back. Test stalled work, panic, saturation and shutdown before attaching request loops. |
| Medium | Image pinning has no complete durable resolution boundary | `RunSpec::new` accepts tag-only images; `ImageRef::pin` mutates an in-memory value, while stored specs are immutable and there is no durable pin-resolution operation. | **Open C05/W03 gate.** Resolve digest/platform before immutable executable admission, or introduce a separate once-written resolution record. Reject unresolved work at execution. Existing specs can represent pending inputs; their existence is not execution readiness. |
| Medium | A future database version could be opened by older code | `migrate` previously skipped known versions and returned a newer `MAX(version)` without rejecting it. | **Fixed with A01.** Opening an unsupported database version fails closed; tested with version 999. |
| Low | Compatibility wording overpromised postcard evolution | The policy allowed adding a trailing optional field without a format bump, without a reader/defaulting mechanism or compatibility fixture proving this. | **Policy corrected.** Any postcard layout change bumps the format unless old/new reader fixtures prove compatibility. |

## Remaining qualification

- **Blocked by: dedicated production Linux benchmark host and a runnable executor** — repeat resource/isolation checks and obtain Sentinel end-to-end p95 on the target hardware.
- **Blocked by: real-network/operator-owned DERP test setup** — Tailcat relay-only, failure/restart and NAT qualification.
- **Blocked by: fault-injecting SQLite VFS or equivalent power-loss test environment** — mid-fsync durability testing.
- Before W02, enforce the single-controller ownership contract in process startup; SQLite serializing writes is not a multi-controller scheduler design.

The [TODO tracker](../TODO.md) carries these gates. Historical completion-log rows remain historical evidence; C06's follow-up completion records closure of the resolver finding.

## Verification after A01

Passed on 2026-09-14: Windows `cargo fmt-check`, `cargo lint`, `cargo test-cli`, `cargo release-cli`; Linux x86_64 WSL2 `cargo lint-linux`, `cargo test-linux`, `cargo release-linux`. The changed authorization/store code is feature-independent. There are 10 new authorization integration tests and one indexed-query-plan test; the existing state/parser/protocol/storage/crash and combined Linux lifecycle suites also pass. Markdown links, fences, stable task IDs and `git diff --check` were checked. No production benchmark was added or rerun by this audit.
