# Sentinel development TODO

Status: Part 01 (F01–F07) and C01–C03 complete: Rust workspace, CLI/configuration, Linux process lifecycles, contributor workflow, tracing/timing/bounded-work foundations, the benchmark runner with a WSL2 rootless-runtime baseline, the measured Lockwell CI/VPS baseline, and the SQLite/Podman/reflink/Tailcat feasibility probes. The CI engine and job execution are not implemented yet.

**Build a purpose-built Rust CI engine for maximum performance.** Primary target: representative warm PR required-check completion **p95 < 60 seconds on the same hardware previously taking >=300 seconds**, with the declared assertions and freshness policy preserved. Support multiple organizations, personal repositories, remote workers, first-class caching, OAuth CLI/MCP, and agent-manageable secrets.

## How to use this backlog

- Work in small runnable increments. Start with Part 01 and follow the first vertical slice below; do not wait for an entire later subsystem before connecting working pieces.
- `[ ]` means unfinished; `[x]` means implemented and verified. Keep stable task IDs when splitting/reordering work. Mark blocked items with `Blocked by: <ID or concrete prerequisite>`; record why, not a guessed completion date.
- Mark a task complete only with its code/docs plus relevant verification. Record the commit and test/benchmark evidence in the completion log. A scaffold, mock, or proposed API alone does not complete behavior.
- Keep this file as the execution tracker; [plan.md](plan.md) remains the design reference. Resolve a design change in both documents before treating it as accepted scope.
- Preserve the separate server/worker execution boundary, tenant ownership, durable transitions, and bounded resource usage as features are added. Introduce crates when useful rather than creating an empty crate for every planned module.
- Add meaningful behavior/failure tests for the contracts being implemented. Run formatting, lint, applicable tests, and changed performance fixtures; do not add implementation-mirroring tests merely to increase counts.
- Optional runtime/build-system features in Part 16 require explicit promotion. Lockwell adapts to Sentinel; its six old workflows are not Sentinel v1 release gates.

### Design references

| Reference | Purpose |
|---|---|
| [Architecture and product plan](plan.md) | Execution, scheduling, storage, tenants, release goals |
| [Performance research](docs/performance-research.md) | Blacksmith/Depot mechanisms, actual Lockwell timings, cache design and benchmark rules |
| [OAuth and secrets](docs/auth-and-secrets.md) | Human/agent authentication, scopes, secret management and injection |
| [Lockwell migration](docs/lockwell-migration.md) | Repository-side adaptation and per-lane parity |

## Development order and checkpoints

The parts are work packages, not a requirement to finish every checkbox in numeric order. Dependencies below identify the working contracts required to start a package; later verification can depend on subsequent packages without blocking the initial implementation.

| Part | Work package | Starting dependencies | Plan milestone |
|---|---|---|---|
| 00 | Completed groundwork | None | M0 |
| 01 | Rust foundation and measurement harness | None | M0–M1 |
| 02 | Core contracts, SQLite and pipeline compiler | Part 01 | M1 |
| 03 | Identity, tenants and registration | Core ownership schema in Part 02 | M1–M2 |
| 04 | First durable server/worker execution | Parts 02 and basic authorization in 03 | M1 |
| 05 | GitHub App and PR feedback | Parts 03–04 | M1 |
| 06 | Local storage, artifact and log durability | Core transitions/spool in 04 | M1–M3 |
| 07 | Local cache, compiler and image fast paths | Worker in 04; publication primitives in 06 | M3, prototype earlier |
| 08 | Fleet scheduling, recovery and Tailcat | Part 04; ownership from 03 | M2 |
| 09 | OAuth server and developer CLI | Parts 03–05 API contracts | M4, basic CLI already in 04 |
| 10 | Secret management and execution binding | Parts 03–04; OAuth for full CLI flow in 09 | M1 foundations / M4 completion |
| 11 | Structured diagnostics and MCP | Parts 06 and 09 | M4 |
| 12 | Human web interface | APIs from 03–11 as available | M1 thin page / M4 completion |
| 13 | Retention, S3, backup and operations | Parts 06–08; key handling in 10 | M3–M5 |
| 14 | Same-hardware optimization and pilots | Baseline in 01; first run in 04 | Continuous / M5 |
| 15 | Release and self-hosting | Required parts above | M5 |
| 16 | Incremental and optional features | Measured need and explicit scope decision | Not automatic v1 gates |

### First vertical slice — start here

**Working outcome:** a locally bootstrapped authorized operator submits a pinned fixture pipeline through the CLI; the server durably assigns it to a separately running worker; the worker executes an isolated job; logs and final status are retrievable; cancellation and restart leave truthful state.

Sequence: `F01–F05` -> `C01–C05` -> `A01–A03` -> `W01–W09`. Implement the minimum working scope of these parts first, then complete their remaining cases. Use a dedicated Linux test host/VM for rootless runtime checks; Windows/macOS CLI development does not substitute for Linux executor validation.

After that, connect one GitHub App repository through Part 05 and run the first local-cache experiment in Part 07. Baseline capture and performance instrumentation begin in Part 01, not after the UI is finished.

## Part 00 — Completed groundwork

- [x] **P01** Preserve the original dashboard/history on `legacy`; create fresh-history default `main`. Evidence: legacy `ba6c583`, new baseline `4b85877`.
- [x] **P02** Write the architecture, performance research, OAuth/secrets contract, and Lockwell adaptation notes. Evidence: planning commits through `3c92be5`; this is research/design, not implementation or measured Sentinel performance.
- [x] **P03** Break development into this dependency-ordered backlog and link it from the project entry points.

## Part 01 — Rust foundation and measurement harness

- [x] **F01** Initialize a minimal Rust workspace, pin the supported toolchain, commit the lockfile, and establish Linux server/worker plus Linux/macOS/Windows CLI build targets. Record library choices and production/build-time dependency boundaries. See [Rust foundation](docs/rust-foundation.md) and the completion evidence below.
- [x] **F02** Add `sentinel server`, `sentinel worker`, and CLI entry points with typed configuration, version information, explicit data paths, validation, and graceful shutdown. No execution from the server process. See [CLI and configuration](docs/configuration.md) and completion evidence below.
- [x] **F03** Establish developer commands for formatting, lint, tests, and release builds; document Linux runtime prerequisites and a local two-process development setup. Keep generated runtime data and credentials out of Git. See [Development](docs/development.md) and completion evidence below.
- [x] **F04** Add structured internal tracing, request/run/job/attempt IDs, monotonic duration measurement, bounded queues, and an explicit blocking/CPU-work boundary. Define the end-to-end timing fields before job execution exists. See [runtime foundations](docs/runtime-foundation.md) and completion evidence below.
- [x] **F05** Create a reproducible no-op workload and machine-readable benchmark runner recording source/image/tool revisions, CPU/RAM limits, filesystem/runtime, warm state, elapsed time, CPU/RSS and I/O. Establish the direct-rootless-runtime baseline on an identified Linux machine. See [Benchmarking](docs/benchmarking.md) and completion evidence below.
- [x] **F06** Capture representative current CI/Lockwell baseline data and identify the physical topology behind its multiple runner names. Measure isolated versus concurrent commands; separate compiler work, tests, waiting and cgroup throttling. Record unavailable hardware access as a blocker rather than invent results. See [CI baseline](docs/ci-baseline.md) and completion evidence below.
- [x] **F07** Run bounded feasibility probes for SQLite commit/dispatch, Podman resource enforcement, reflink versus safe directory copy, and Tailcat unattended connectivity. Record findings/decisions, retaining only useful fixtures and code. See [feasibility probes](docs/feasibility-probes.md) and completion evidence below.

**Checkpoint:** reproducible builds, runnable process shells, a known Linux execution target, and recorded baseline/timing format. Runtime skeletons do not count as a working CI job.

## Part 02 — Core contracts, metadata and pipeline compiler

- [x] **C01** Define stable tenant/repo/run/job/step/attempt/worker IDs and the run/job state machine, terminal aggregation, transition permissions, timestamps, failure classes, and cancellation desired state. See [core contracts](docs/core-contracts.md) and completion evidence below.
- [x] **C02** Implement local SQLite migrations, WAL/foreign keys, ownership constraints, indexed queries, short transactions, a blocking writer path, and documented commit acknowledgement policy. Create tables as their behavior is implemented. See [storage](docs/storage.md) and completion evidence below.
- [x] **C03** Define versioned API errors, idempotency keys, event sequence/cursors, protocol size limits, worker capability negotiation, and supported version mismatch behavior. See [protocol contracts](docs/protocol.md) and completion evidence below.
- [ ] **C04** Implement bounded strict `.sentinel.yml` parsing: version check, duplicate/unknown-key rejection, YAML limits, deterministic compilation, valid IDs/paths, finite timeouts and resource policy. Publish the first schema with valid/invalid fixtures.
- [ ] **C05** Compile image/run/steps/env/workdir/resources and DAG dependencies; reject cycles/missing jobs; specify shell failure semantics and pinned source/image inputs. Keep the compiled spec immutable per run and distinguish rerun from new dispatch.
- [ ] **C06** Add the bounded expression grammar, event/ref filters, concurrency keys, dependency outcome conditions, policy defaults, and `hash_files` evaluation phases/limits. Prevent expressions from becoming arbitrary execution or network calls.
- [ ] **C07** Define cache/secret/artifact bindings in the schema and implement offline `pipeline validate`/`explain`, including unresolved runtime inputs and missing-permission diagnostics. Do not present unresolved hashes or credentials as validated values.
- [ ] **C08** Verify transitions and parser limits with meaningful malformed-input, duplicate request, transaction rollback, conflicting update and crash-reopen cases; publish the schema/API compatibility policy.

**Checkpoint:** a pipeline compiles deterministically into tenant-owned durable work with an explicit execution/result contract. Incremental syntax from Part 16 is not implicitly accepted.

## Part 03 — Identity, tenants and registration

- [ ] **A01** Implement tenant namespaces, users/external identities, memberships, repo grants and super-admin/tenant-admin/operator/reader/service-account authorization. Enforce ownership in repository queries rather than trusting caller-supplied tenant context.
- [ ] **A02** Implement host-local first-admin bootstrap, local login with maintained password hashing, opaque sessions, expiry/revocation, secure cookies/CSRF, and audited recovery. Disable bootstrap afterward and prevent removing the last active super admin.
- [ ] **A03** Provide a host-local provisioned, scoped, expiring development/service credential so the first CLI/API slice is authenticated before browser OAuth is complete. Hash token secrets; reuse the final authorization layer rather than adding a no-auth dev bypass.
- [ ] **A04** Add GitHub user sign-in and verified identity linking; preserve immutable provider user IDs, validate state/redirects, and keep login tokens separate from installation tokens.
- [ ] **A05** Implement closed/invite-only/approval-required registrations, expiring one-use invitations, pending/approved/rejected users, and tenant creation/install-binding permissions. Existing users can still sign in when registrations are closed.
- [ ] **A06** Add privileged account MFA/recovery codes and step-up for auth/registration/super-admin policy changes; implement account/session administration and logout-all without plaintext credential exposure.
- [ ] **A07** Implement tenant suspension, membership/role revocation, pool grants, and audit records; revoke active subscriptions/tokens and request job cancellation under documented policy.
- [ ] **A08** Test two organizations and a personal namespace with overlapping memberships, pending/unbound installs, invitation reuse/races, guessed IDs, cross-tenant queries/downloads/cursors, and last-admin recovery. Extend these tests as storage/MCP are connected.

**Checkpoint:** authentication is distinct from admission; a user or installation cannot allocate another tenant's compute or read its data. Basic authorization must precede private repository execution.

## Part 04 — First durable server/worker execution

- [ ] **W01** Implement expiring single-use worker enrollment, worker-generated identity, scoped pool access, authenticated persistent direct-TLS sessions, heartbeat and protocol negotiation.
- [ ] **W02** Implement durable ready queue, transactional resource reservations, fenced attempt leases and offer acknowledgement; wake immediately on enqueue/completion rather than heartbeat polling.
- [ ] **W03** Add exact-revision checkout/preparation, fresh workspaces and a rootless Podman executor with resource limits, user namespaces, restricted mounts/network access, dropped capabilities, and tracked process ownership.
- [ ] **W04** Run sequential steps with specified shell/env/workdir semantics; collect exit/signal/OOM/timeout and phase timings. Separate preparation/runtime/infrastructure failures from failed commands.
- [ ] **W05** Capture bounded stdout/stderr frames, dynamic redaction registration, a durable worker spool, sequence acknowledgements and basic API/CLI tail/follow. Slow consumers cannot cause unbounded RAM or silently lose logs.
- [ ] **W06** Implement desired-state cancellation, graceful/forced process-group termination, queue/execution timeouts, lease expiry and capacity release. Never automatically replay uncertain side-effecting work.
- [ ] **W07** Implement crash/restart reconciliation of reservations, leases, owned containers/workspaces and resumable spool uploads; reject stale completion/publication using attempt fencing.
- [ ] **W08** Expose dispatch/status/rerun/cancel/worker status through the shared API and a minimal human/JSON CLI; add the first thin run/status/log web page using the same API.
- [ ] **W09** Exercise the vertical slice: success, command failure, duplicate offer, lost ack, cancel during preparation/run, worker/controller restart, stale lease and network loss. Verify no duplicate healthy-session execution and no orphaned owned processes after recovery.

**Checkpoint:** an authorized job runs outside the server, reports durable truthful status/log completeness, and recovers predictably. Record ready-to-first-process latency now.

## Part 05 — GitHub App and PR feedback

- [ ] **G01** Implement App installation/repository binding for org and personal accounts, scoped short-lived source tokens, permission validation and installation lifecycle updates.
- [ ] **G02** Add raw-body webhook signature verification, size limits, durable delivery dedup/acknowledgement and asynchronous bounded pipeline/source resolution.
- [ ] **G03** Implement push/PR/tag/manual source policies, exact head/base/source SHA provenance, duplicate-event policy and immutable compiled-run creation. Unknown installation/config failure must produce explicit outcomes.
- [ ] **G04** Implement a durable Checks outbox with retry/backoff/rate-limit handling, per-job and stable required aggregate checks, `details_url`, correct conclusions and stale-attempt protection.
- [ ] **G05** Handle rerequests and ambiguous check-creation responses without uncontrolled duplicates; reconcile interrupted deliveries/check updates and installation access removal/rename/transfer.
- [ ] **G06** Verify a real PR on a dedicated pilot repo: pass/fail/config error/cancel/rerun/new push and `gh pr checks`. Record webhook, source resolution, dispatch and GitHub propagation independently.

**Checkpoint:** the first real PR receives accurate Sentinel checks. Already-accepted work does not wait on GitHub status synchronization.

## Part 06 — Local storage, artifacts and log durability

- [ ] **D01** Implement tenant-scoped immutable object/manifests: streaming temp writes, digest/length verification, flush/atomic rename/directory flush, then reference commit. Detect orphan/incomplete/corrupt objects on recovery.
- [ ] **D02** Add resumable idempotent uploads and authorized range/download reads with bounded transfer concurrency, active-reader tracking and traversal/symlink escape protection.
- [ ] **D03** Implement artifact declarations, success/failure/always capture, required/optional missing-file semantics, per-run size limits, checksums and retention metadata. Basic capture must not depend on optional user-defined finalizer syntax.
- [ ] **D04** Finish segmented log storage, sparse step/time/line indexes, compression of sealed segments, cursor replay and worker-spool acknowledgement. Define partial/gap/truncated records and durable completion boundaries.
- [ ] **D05** Make finalization persist required outcomes/artifacts/log status before terminal publication; optional cache replication is separate bounded background work. Record degraded/lost data truthfully.
- [ ] **D06** Enforce disk admission watermarks, reserved metadata/spool space and initial storage quotas before real noisy/large jobs. Add reader/lease-safe object lifecycle hooks for later GC.
- [ ] **D07** Test crash between object/manifest operations, interrupted upload, checksum mismatch, disk full, overlong/binary logs, slow readers, spool loss and cross-tenant object access. Verify bounded RAM and explicit completeness.

**Checkpoint:** local storage works without a separate storage service; uploads and crashes cannot publish incomplete objects as complete evidence.

## Part 07 — Local cache, compiler and image fast paths

- [ ] **K01** Implement separate cache classes/compatibility metadata for downloads, materialized dependencies and compiler intermediates; include tenant/repo/trust/platform/toolchain boundaries and explainable hit/miss reasons.
- [ ] **K02** Implement immutable cache generations and job-private writable clones using capability-detected reflinks plus safe copy fallback; benchmark a whole-tree snapshot backend before adopting it.
- [ ] **K03** Publish cache generations atomically with active-use leases, bounded concurrent writers and authorized promotion. Corruption/incompatibility becomes a miss; PR writers cannot poison protected-branch state.
- [ ] **K04** Implement local Git object mirrors with serialized incremental fetch, exact-SHA verification, stable workspace paths and reader-safe GC. Measure worktree materialization separately from fetch.
- [ ] **K05** Keep digest-pinned runtime images pulled/unpacked through the supported runtime's content store; implement bounded prefetch and immutable-download stampede suppression. Preserve private-image authorization.
- [ ] **K06** Persist compiler state across small source/lockfile edits with tool-owned invalidation; prove normal/race/coverage/experiment and architecture compatibility. Do not equate compiler-cache reuse with cached test outcomes.
- [ ] **K07** Publish tested cache/environment recipes for Go, Rust, npm/pnpm/Bun, Python, Maven/Gradle, plus a custom-tool fixture. Measure cold, warm, small-edit, changed dependency and changed toolchain cases.
- [ ] **K08** Add worker cache/image availability summaries, first-touch/restore/commit/dirty-byte/copy/lock-wait metrics, and trace where a nominal hit costs more than a rebuild. Feed placement in Part 08.
- [ ] **K09** Verify concurrent clone/write isolation, canceled writers, cache eviction during active use, tampered state, trust change and disk pressure. Publish no-op and incremental-build before/after results on fixed hardware.

**Checkpoint:** the second run spends materially less time preparing/recompiling without sharing writable job state or skipping required tests. Cache mount latency is not reported as the full read/materialization cost.

## Part 08 — Fleet scheduling, recovery and Tailcat

- [ ] **Q01** Extend admission across workers with hard CPU/RAM/disk/architecture/runtime/label/trust/pool constraints and reserved host resources. Reject unsatisfiable jobs with explicit reasons.
- [ ] **Q02** Implement tenant -> repo fairness/aging, per-repo concurrency and resource-aware backfill; reserve a path for large jobs and PR feedback under long manual workloads.
- [ ] **Q03** Score eligible workers by expected completion, cache/image locality and measured load; bound locality waiting and avoid oversubscribing a host with multiple worker identities.
- [ ] **Q04** Implement superseded-run cancellation, worker drain/revoke and queued-job explanations with age/missing resources. Keep lease ownership distinct from repository concurrency groups.
- [ ] **Q05** Separate control priority from bulk transfers; add reconnect jitter, event replay, expired-lease handling and fleet-level restart reconciliation.
- [ ] **Q06** Integrate a pinned optional Tailcat helper for only the Sentinel endpoint, persistent identities and authenticated enrollment; document direct TLS fallback and operator-owned DERP/map configuration.
- [ ] **Q07** Expose direct/relay path, RTT, reconnects, helper version and throughput; test helper restart, changing endpoints, NAT failure, relay-only operation and revoked peers. Keep credentials out of diagnostics.
- [ ] **Q08** Implement portable checksummed remote cache hydration with bounded transfers/resume, compatible scopes and a restore-cost/deadline policy. Do not make every local hit traverse the controller or WAN.
- [ ] **Q09** Verify a three-worker fleet under bursts/partitions/restarts, stale completions, draining, mixed capacities and noisy tenants; then load-test 100 worker sessions and 10,000 queued jobs, identifying simulation versus real executor coverage.

**Checkpoint:** eligible free capacity receives work promptly; load balancing does not trade correctness or starvation for cache hits. Tailcat works with self-hosted relay infrastructure.

## Part 09 — OAuth server and developer CLI

- [ ] **O01** Implement integrated authorization-server metadata, first-party public client registration, authorization code + PKCE S256, redirect/state/resource binding, consent and scoped tenant/repo grants.
- [ ] **O02** Implement hashed opaque access/refresh tokens, short access lifetime, refresh rotation/replay handling, revocation/logout, and indexed authorization without a GitHub request per command/log frame.
- [ ] **O03** Implement device authorization: public verification/user code, private device code, expiry, denial, polling interval and slowdown handling. Admission policy applies to both browser and device login.
- [ ] **O04** Implement CLI `auth login`, `--device`, `status`, `logout` and deployment/tenant profiles; OS credential storage or owner-only fallback outside repos; serialize concurrent refresh safely.
- [ ] **O05** Complete CLI status/run/list/dispatch/rerun/cancel/log/search/wait, worker/queue/cache/artifact and pipeline commands with human/JSON/NDJSON, pagination and stable exit codes. `wait` uses bounded event subscriptions.
- [ ] **O06** Implement scoped expiring service-account grants and actionable `doctor`/auth errors; existing authorized agent sessions can run commands without new login prompts or revealing credential material.
- [ ] **O07** Verify browser/device login, rejected redirects/verifiers/audiences, refresh races, lost responses, revoked membership, server-profile confusion and logout on Linux/macOS/Windows CLI builds.

**Checkpoint:** a human logs in once and an authorized coding agent can use the same credential profile; GitHub access tokens are never accepted as Sentinel tokens.

## Part 10 — Secret management and execution binding

Implement storage/redaction/injection foundations alongside Part 04 **before running any job with secrets**; completing browser OAuth is not a prerequisite for testing these contracts with scoped local credentials.

- [ ] **S01** Implement versioned authenticated encryption with a maintained AEAD library, unique nonces and authenticated ownership context; master key outside SQLite, with rotation/backup handling.
- [ ] **S02** Implement tenant/repo/job/step bindings and repo allowlists, explicit precedence, `secrets:write` delegation independent of operator/admin roles, metadata-only reads and audited use/version IDs.
- [ ] **S03** Implement CLI secret set/rotate/list/describe/delete using hidden prompt/stdin/protected file input, explicit byte/newline/size rules, JSON metadata output and optimistic version/idempotency checks.
- [ ] **S04** Add atomic env-file import with documented parsing and metadata-only preview; reject duplicate/invalid entries and never perform shell/dotenv expansion or echo values.
- [ ] **S05** Resolve allowed secret versions during preparation, bind delivery to worker/attempt, inject only declared file/env bindings, and define rerun current-versus-original version behavior.
- [ ] **S06** Register redaction before execution, handle values split across frames, exclude secret paths from default artifacts/caches and remove injected files/processes after completion/cancel/restart.
- [ ] **S07** Verify an authorized agent provisions a secret via CLI and a job uses it; test scope denial, revoked versions, retry/import races, key restore and absence of plaintext in logs/errors/audit/artifacts/CLI output.

**Checkpoint:** agents can manage secrets through secure input using their granted authority; metadata inspection cannot retrieve plaintext, and use is traceable without logging values.

## Part 11 — Structured diagnostics and MCP

- [ ] **X01** Define the versioned report/diagnostic contract with source/test/step references, evidence offsets, failure class, provenance and fresh/advisory/incomplete distinctions; command exit state stays authoritative.
- [ ] **X02** Implement bounded Go JSON, Rust compiler JSON and JUnit ingestion plus custom-report input. Repository-specific evidence adapters stay in repositories, not Sentinel's core.
- [ ] **X03** Implement failure selection/context with fallback tail, indexed literal search, incremental cursors and response limits: default 8 KiB / 20 diagnostics, hard ceiling 64 KiB, explicit truncation/completeness.
- [ ] **X04** Implement MCP stdio tools/resources over the API using CLI credential profiles: list/get/wait/failure/logs/queue/pipeline validation plus scoped dispatch/rerun/cancel and secret metadata.
- [ ] **X05** Implement Streamable HTTP MCP protected-resource metadata, OAuth discovery/PKCE, audience checks, origin/session handling and the chosen protocol version. No upstream token passthrough.
- [ ] **X06** Support the client registration/metadata discovery methods needed by selected clients, with bounded metadata retrieval and policy; user registration and OAuth client registration remain distinct.
- [ ] **X07** Exercise at least two target MCP clients through login/refresh/revoke/reconnect/scope-denial; verify stdio never attempts HTTP OAuth redirects on its transport.
- [ ] **X08** Demonstrate an agent finds the actual error in a 100 MiB noisy fixture using bounded responses and stable evidence, then reruns; verify malformed reports, prompt-like log text and oversized/binary output cannot change control behavior.

**Checkpoint:** diagnosing a failure does not require dumping whole logs or buying model inference. Same scopes and repository authorization apply to CLI, UI and MCP.

## Part 12 — Human web interface

- [ ] **U01** Choose a small UI stack through a measured accessible log-view prototype; embed build assets in the Rust server with no mandatory Node/Deno production process. Start with the thin Part 04 run page.
- [ ] **U02** Build login/tenant context, run filters by repo/ref/PR/SHA, run detail, DAG and phase/step timing, linked failure summaries, artifacts and authorized cancel/rerun.
- [ ] **U03** Implement virtualized streaming logs with folded successes, indexed search/context, deep links, resumable cursors and visible truncation/gaps; avoid per-line full-tree rendering.
- [ ] **U04** Build worker capacity/reservations/drain views, queue explanations, cache hit/miss/backend/size diagnostics and GitHub synchronization lag.
- [ ] **U05** Build super-admin registration/tenant/pool/quota/audit views and tenant-scoped membership/repository/secret-metadata administration; expose no stored secret values.
- [ ] **U06** Verify keyboard/screen-reader navigation, contrast/responsive layouts, role changes during open sessions, slow reconnecting streams and bounded memory/DOM on large logs.

**Checkpoint:** a human can find the same failure, evidence and queue reason as an agent, with authorized actions and clear active tenant scope.

## Part 13 — Retention, optional S3, backup and operations

- [ ] **R01** Complete byte/age quotas and retention at deployment/tenant/repo/run levels, active-use-safe LRU/GC, stale upload cleanup, disk watermarks and reserved metadata capacity. Choose defaults from measured hardware.
- [ ] **R02** Implement the optional external S3 blob adapter with explicit endpoint/region/bucket/prefix/TLS/credentials, multipart streaming, checksum/range/resume support and abort cleanup; SQLite metadata stays local.
- [ ] **R03** Define and implement S3 degraded durability/spool/admission behavior; distinguish optional cache failures from required artifact persistence. Verify a named endpoint compatibility matrix.
- [ ] **R04** Implement consistent online metadata + manifest/object backup, integrity verification, secret-key backup instructions and a restore command/procedure. Set recovery-point/time objectives and measure a drill.
- [ ] **R05** Implement versioned data/protocol upgrades, supported server/worker skew, pre-upgrade checks, migration failure handling and rollback compatibility documentation.
- [ ] **R06** Add scrapeable counters/histograms, health/readiness, internal queue/spool/disk/auth/GitHub metrics and sanitized diagnostic bundles. Verify idle RSS/CPU budgets on the reference host.
- [ ] **R07** Test sustained pressure, interrupted GC/backup, corrupt/missing objects, S3 outage, expired credentials, schema upgrade interruption and recovery onto a replacement host.

**Checkpoint:** the default installation needs only its own local storage; optional external storage and upgrades fail visibly and recovery is demonstrated, not just documented.

## Part 14 — Same-hardware optimization and repository pilots

Run this work from the first executable slice onward; do not postpone performance until feature completion.

- [ ] **B01** Freeze representative benchmark/check contracts, hardware/total resource allocations, tool/image/source/SDK versions, result freshness and cold/warm/small-edit conditions. Extend the Part 01 baseline with identical-isolation comparisons.
- [ ] **B02** Benchmark direct runtime, healthy GitHub self-hosted runner, Woodpecker and Sentinel where available; clearly identify hosted Blacksmith/Depot hardware differences and missing comparison access.
- [ ] **B03** Meet/measure the [plan's latency/resource budgets](plan.md#12-performance-targets-and-evidence): dispatch p95 <100 ms, warm first process p95 <2 s, visible logs p95 <250 ms and indexed failure query p95 <200 ms on specified fixtures. Publish distributions/sample counts, not a single fastest run.
- [ ] **B04** Profile source/image/cache materialization, build/test execution, disk wait, CPU throttling, lock wait and required output publication; optimize the largest measured critical-path cost and preserve before/after artifacts.
- [ ] **B05** Validate cache usefulness across Go/Rust/JS/Python/Java/custom-tool workloads, large directory trees and 10 GiB cache fixtures; measure first-touch, dirty bytes, transfer/copy amplification and tail latency under concurrency.
- [ ] **B06** Adapt selected Lockwell PR lanes to Sentinel commands/cache/report contracts; update corresponding repository CI contract tests/docs without introducing Lockwell-specific engine behavior. Record still-external lanes explicitly.
- [ ] **B07** Investigate/remove false dependencies and redundant compatible builds; optimize repository fixture/readiness waits or shard independent tests only with equal assertions and the same total resource budget. Keep `-count=1`, race/fuzz/coverage obligations unless separately reviewed as a policy change.
- [ ] **B08** Demonstrate the primary target: representative warm required-check completion p95 <60 s against an >=300 s same-hardware baseline. Keep first-failure, required pass and long audit/acceptance timings distinct; publish unresolved lower bounds if the target is not yet met.
- [ ] **B09** Run reliability/performance combinations: bursts, 1/3/10 real workers where available, slow/full disk, direct/relay links, network loss, restarts and noisy tenants. Set a noise-aware regression gate, initially 10% p95 overhead regression.
- [ ] **B10** Shadow pilot checks with separate names/data/resources; verify per-lane parity and then switch required checks/disable replaced Actions with documented rollback. Include two orgs and a personal namespace; full Lockwell workflow parity is not required.

**Checkpoint:** published performance evidence matches scope and hardware. Correctness or full-check freshness is never traded away invisibly to reach a headline number.

## Part 15 — Release and self-hosting

- [ ] **V01** Ship Linux x86_64/arm64 server/worker packages and Linux/macOS/Windows CLI, checksums, build instructions, dependency/license inventory and documented verification of release artifacts.
- [ ] **V02** Provide systemd and supported container deployment examples, separate service identities/data directories, TLS/proxy/GitHub ingress configuration and fully local operation instructions.
- [ ] **V03** Finish onboarding: bootstrap admin, register/approve tenant, bind App/repos, enroll direct/Tailcat worker, OAuth CLI/MCP login, set secret, run pipeline, inspect failure and restore backup.
- [ ] **V04** Bootstrap Sentinel's own development checks using local commands or a documented temporary existing executor, then dogfood the supported checks on Sentinel with a recovery path independent of a broken Sentinel deployment.
- [ ] **V05** Complete end-to-end release qualification for fresh install, upgrade, recovery, multi-tenant revocation, worker loss, secrets, caches, bounded diagnostics and API/schema/client compatibility.
- [ ] **V06** Publish feature/support limits, actual benchmarks and remaining performance blockers; tag v0.1 only with required correctness/operational gates met. Keep the sub-minute claim explicitly unmet until `B08` has evidence; it cannot be checked off through a documentation exception.

**Checkpoint:** a new operator can run the supported CI locally without a Sentinel cloud account, usage license, or mandatory external database/object-store service.

## Part 16 — Incremental and optional backlog

These are deliberately not assumed dependencies for the first runnable engine or v0.1. Promote an item with its CI use case, design scope, owner/dependencies, and measurement/verification gate. Basic schema bindings/worker cleanup already required above remain required.

- [ ] **I01** Named pipelines and bounded typed manual inputs, each with independent triggers/concurrency/check identity; no built-in Lockwell workflow names.
- [ ] **I02** Durable UTC schedules with deduplicated occurrences, overlap policy, bounded missed-occurrence handling, pinned source revision and tenant suspension behavior.
- [ ] **I03** Additional authorized repository checkouts/full-history selection and complete source manifests; preserve grant checks and exact rerun revisions.
- [ ] **I04** Declared non-secret step/job outputs, artifact handoff and bounded user-defined finalizers; keep independent worker cleanup/fencing authoritative on cancellation or expiry.
- [ ] **I05** Shared external-resource leases/locks where job-private resources cannot remove contention; separate them from supersession/concurrency and verify stale-owner fencing.
- [ ] **I06** Conservative opt-in task-result reuse with complete declared inputs, appropriate sandbox constraints, provenance and explicit `reused`/force-fresh results; never enable arbitrary-shell success caching by default.
- [ ] **I07** Optional compiler/build-tool remote-cache protocol adapters, builder state persistence and manifest/dedup improvements, selected from actual I/O/compile profiles.
- [ ] **I08** Optional Docker/Compose or microVM execution after cross-workload justification, isolation/lifecycle design and same-hardware startup/resource benchmarks; no mandatory VM pool.
- [ ] **I09** Hostile fork support only with an appropriate sandbox/pool/cache/secret/egress boundary and failure tests; rootless containers alone are not sufficient.
- [ ] **I10** Bounded matrices, reusable pipelines, service containers, deployment/OIDC capabilities and native multi-arch build orchestration only as proven CI needs. Repository scripts may already cover them without core changes.
- [ ] **I11** GitHub merge-queue `merge_group` handling before migrating any repository that uses it; correct tested SHA and required-check semantics are a per-repo gate.
- [ ] **I12** Windows/macOS workers, multiple active controllers, external SSO providers or cloud autoscaling as separate designs; no unreviewed shared-SQLite HA mode.
- [ ] **I13** Profile-driven advanced I/O/allocator/snapshot/boot improvements; retain only measurable wins with maintenance and portability costs recorded.

## Completion log and handoff

Append concise entries as work lands; reference existing test reports/benchmark artifacts rather than pasting raw logs. Keep failed performance targets and environment blockers visible.

| Tasks | Evidence | Result |
|---|---|---|
| P01–P02 | `4b85877`, `39d833f`, `3c92be5`; linked design/research docs | Repository/planning groundwork complete; engine not implemented |
| P03 | This backlog and entry-point links; Markdown/ID/dependency validation | Development parts prepared |
| F01 | Commit titled `build: initialize pinned Rust workspace and platform contract`; [foundation documentation](docs/rust-foundation.md); verification on 2026-09-13 | Rust 1.97.0, committed lockfile, one package, zero external dependencies. Format/Clippy passed; test harness passed with 0 tests; Windows x86_64 release build and stderr/exit-code smoke check passed. All six documented CLI targets passed `cargo check`; both Linux targets passed server/worker/combined checks; all four non-Linux targets rejected each Linux role feature as expected. Metadata/dependency tree verified. Cross-target checks do not establish native linking/runtime support. |
| F02 | Commit titled `feat: add CLI configuration and Linux process lifecycles`; [configuration contract](docs/configuration.md); verification on 2026-09-13 | Windows x86_64 portable tests (3) and Linux x86_64 WSL2 tests (3 CLI-only; 7 each for server-only, worker-only and combined) passed. Linux process tests cover SIGINT/SIGTERM/SIGHUP for enabled roles. Windows/Linux Clippy and format passed; Linux combined-role release build passed; six CLI targets and both Linux combined-role targets compile-check. No job runtime or durability claim. |
| F03 | Commit titled `build: add contributor commands and development guide`; [Development](docs/development.md); verification on 2026-09-13 | All four portable aliases passed on Windows x86_64 and Linux x86_64 WSL2; all five Linux lint/test/release aliases passed. Both development aliases passed no-write config checks, ran concurrently, and exited cleanly on SIGINT. Markdown links/fences and Git ignore behavior verified. Linux executor prerequisites documented; Podman isolation/performance qualification remains future work. |
| F04 | Commit titled `feat: add tracing timing and bounded execution foundations`; [runtime contract](docs/runtime-foundation.md); verification on 2026-09-13 | Windows portable checks/tests/release passed; Linux WSL2 lint, 8 foundation tests + 9 process tests in each server-only/worker-only/combined build, and combined release build passed. Six CLI targets and both Linux combined-role targets compile-check. Tests cover ID propagation, timing/outcomes, JSON errors, queue saturation, sink stalls/failures, panic recovery and timeout capacity accounting. CLI production tree remains clap-only. Lifecycle timings are real; CI phases are defined but unmeasured. |
| F05 | Commit titled `feat: add benchmark runner and no-op rootless baseline`; [Benchmarking](docs/benchmarking.md); record `bench/f05-noop-baseline.jsonl`; verification on 2026-09-13 | New `sentinel-bench` crate (clap/serde/serde_json/libc). Runner tests (3) passed on Windows x86_64 and Linux x86_64 WSL2; existing 8+9 role tests, format, Clippy and release builds passed on both. Baseline on `DOOMBRINGER` (i7-13700KF, Ubuntu 24.04 WSL2, ext4, rootless Podman 4.9.3/runc/cgroup v2, busybox by digest): direct `true` median 0.25 ms; `podman run --rm` no-op median 250 ms warm, 223 ms cold-storage single sample, 252 ms with `--cpus 1 --memory 256m`. WSL2 is a development reference, not a production qualification; limit enforcement is unverified (F07). |
| F06 | Commit titled `docs: record measured Lockwell CI and VPS baseline`; [CI baseline](docs/ci-baseline.md); records `bench/f06-lockwell-ci-runs.jsonl`, `bench/f06-vps-probe.log`, script `bench/f06-vps.sh`; measured 2026-09-13 | Topology: all 16 `lockwell-vps/org/sdk/gate` runners are one 12-vCPU/31 GiB EPYC VPS with cgroup caps of 10 + 8 CPUs (oversubscribed); 5.4% of CFS periods throttled since boot. 25 successful `ci.yml` runs: VPS span median 591 s / p95 1,078 s; critical path is `test-race` 297 s, `integration` 273 s, `docker` 248 s medians; queue wait p95 418 s. Idle-host probe at Lockwell `0c87e018`: unit lane cold 98 s vs warm 63 s (compile ≈ 36 s / 274 CPU-s), warm execution wait-dominated (≈1.3 busy cores; `consensus` 59 s); race lane warm 216 s dominated by `internal/web` 193 s; two concurrent lanes cost +15%/+1% wall with 4x throttling. Docker/integration internals and a probe during live CI remain unmeasured. |
| F07 | Commit titled `feat: add feasibility probes for SQLite, Podman, reflink and Tailcat`; [feasibility probes](docs/feasibility-probes.md); `crates/sentinel-probes`; records `bench/f07-*`; measured 2026-09-13 on WSL2 | SQLite WAL `synchronous=FULL`: enqueue/dispatch commit ≈0.6–0.8 ms median on ext4/XFS (2.3 ms Btrfs), ready pick ≈3 µs with 100k backlog → one durable writer adopted. Rootless Podman enforces `--cpus`, `--memory` (OOM kill observed), `--pids-limit`, `--network none`, read-only rootfs, dropped caps; `io`/`cpuset` not delegated. Reflink clones ≈15 µs/file on XFS/Btrfs versus 1–2 s explicit copy for 20k×16 KiB; ext4 lacks reflink; first read of a clone costs 0.7–1.1 s → `FICLONE` with copy fallback adopted. Tailcat 0.6.0 runs unattended with persistent keys, stable address, allow-list and direct path; `forward` does not recover after server restart → adapter must supervise the helper. Probe tests (2) pass on Windows and Linux. |
| C01 | Commit titled `feat: add core identifiers and fenced job state machine`; [core contracts](docs/core-contracts.md); `crates/sentinel-core`; verification on 2026-09-13 | Typed 16-byte inline IDs with canonical text form; `u64` per-job fence; `JobControl::apply` is a const, allocation-free transition table with actor permissions, strict fence checks and terminal absorption; failure classes map one-to-one onto outcomes; durable `cancel_requested`; derived run aggregation with documented precedence; dependency policies; first-entry-wins UTC timestamps. 16 unit tests (exhaustive state×event×actor sweep, aggregation, IDs) pass on Windows and Linux; workspace lint/format/release pass. No persistence yet (C02). |
| C02 | Commit titled `feat: add SQLite metadata store with durable single writer`; [storage](docs/storage.md); `crates/sentinel-store`; engine comparison `bench/c02-engines.jsonl`; verification on 2026-09-13 | SQLite chosen over redb after same-workload measurement (durable commit ≈0.5 ms both, fsync-bound; SQLite 2x faster non-durable, plus constraints/indexes/backup for free); sled alpha and jammdb unmaintained. Versioned migrations, WAL + FULL sync + foreign keys, `WITHOUT ROWID` tables keyed by 16-byte IDs, tenant predicate on every op, partial ready index verified via query plan, one bounded writer thread whose acknowledgement means fsynced, read-only pooled readers, fenced compare-and-set transitions. 9 integration + 2 codec tests pass on Windows and Linux. |
| C03 | Commit titled `feat: add protocol contracts for errors, idempotency, cursors and negotiation`; [protocol contracts](docs/protocol.md); `crates/sentinel-protocol`; verification on 2026-09-13 | Versioned `sentinel.error/1` shape with eleven stable codes, derived HTTP status and retry policy, zero-sized schema marker that rejects foreign shapes; inline 64-byte idempotency keys with 128-bit body fingerprint and a four-way decision table (execute/replay/in-flight/mismatch, 24 h TTL); dense per-stream `Seq` and fixed 42-byte tenant-bound cursors parsed without allocation; size limits with compile-time invariants; `u64` capability bit set, required-set check, highest-common-version selection, typed final rejections. 13 unit tests pass on Windows and Linux; workspace lint/format/release pass. |

**Next task:** `C04` — bounded strict `.sentinel.yml` parsing: version check, duplicate/unknown-key rejection, YAML limits, deterministic compilation, valid IDs/paths, finite timeouts and resource policy; publish the first schema with valid/invalid fixtures.
