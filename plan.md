# Sentinel — implementation plan

Status: design and acceptance criteria; implementation starts from scratch.
Reviewed: 2026-09-13. Repository: `RusticStack/sentinel`.

## 1. Product contract

Build a fully open-source, self-hosted CI engine optimized for fast feedback on organization **and personal** GitHub repositories. GitHub remains the forge; Sentinel owns execution, scheduling, logs, caches, artifacts, and diagnostics. Borrow Woodpecker's independent-server/runner model and Blacksmith's emphasis on fast startup, local data, and observability.

- Rust control plane, worker, storage modules, CLI, and MCP integration.
- One host to start; multiple heterogeneous workers are a v1 requirement.
- No Sentinel execution-minute pricing, license server, mandatory cloud account, or paid feature gates. Hardware, electricity, bandwidth, optional S3, and GitHub service limits still exist. Capacity and retention limits prevent unattended machines from filling up.
- Near-immediate dispatch when an eligible worker has capacity; explicit explanations when it cannot start.
- Human-readable web UI and bounded, structured, evidence-linked responses for coding agents.
- New implementation and UI in `main`; preserve the old dashboard and its history in `legacy`.
- MIT licensing, public build instructions, protocol/schema documentation, dependency licenses, and reproducible benchmark recipes.

**Performance is an engineering target, not a language guarantee.** Rust gives control over allocation, concurrency, memory, and I/O. It does not make compilation, slow disks, cold image pulls, or WAN links inherently faster. “Fastest on the market” is an ambition to validate with published measurements, not an initial product claim.

## 2. Review of the original plan and repository

| Original assumption | Revised decision |
|---|---|
| One queue, slots on one VPS | Durable event-driven fleet scheduler with resource reservations and fairness |
| Reuse/fork the Fresh UI | New UI; old implementation is reference material |
| Go or Rust; four mandatory processes | Rust workspace; server embeds UI and storage; workers remain separate execution boundaries |
| Dropping Actions guarantees speed | Measure dispatch, preparation, execution, transfer, and total feedback independently |
| Cache is always a snapshot mount | Local CoW fast path plus ordinary-filesystem and remote-transfer paths |
| Hardlink clone is a snapshot substitute | Never hardlink writable jobs into shared caches; writes corrupt other jobs |
| Lockfile-only cache keys | Include trust scope, architecture, image/toolchain identity, and format version |
| Tailed logs are sufficient for AI | Structured diagnostics, contextual excerpts, budgets, cursors, evidence links |
| Concurrency/cancellation/isolation come last | Required before running real repository code |
| SQLite/Postgres/store service undecided | Embedded SQLite metadata; Sentinel-owned file store; optional S3 adapter |
| Fixed week estimates | Evidence-based milestones and release gates |

### Existing Sentinel findings

Inspected `RusticStack/sentinel` at `ba6c583715c16fde498d646577c98bc60c221adb`: README, repository tree, `lib/github.ts`, `lib/realtime.ts`, and LICENSE.

- Deno 2 / Fresh 2.3 monitoring dashboard with GitHub OAuth, an org membership gate, Deno KV sessions, system metrics, and optional Vigil SOC views.
- `lib/github.ts` reads GitHub Actions runners/runs/jobs using a classic PAT. Runner data is cached for 15 seconds; runs/jobs for 30 seconds. Recent-run aggregation scans a bounded subset of repos.
- `lib/realtime.ts` sends dashboard snapshots every 15 seconds. This is monitoring, not execution or scheduling.
- Existing auth assumes one organization; personal installations need a new authorization model.
- Preserve source/history/license. Reuse lessons about navigation and deployment, not a wholesale OAuth/UI port.
- This source does not establish why the reported GitHub runner waits last hours. Labels, runner groups, concurrency, connectivity, and GitHub dispatch need separate evidence. Sentinel must expose these conditions rather than inherit opaque waits.

### Scope boundaries

V1: Linux x86_64/arm64 server/workers; org and personal GitHub App installations; own YAML; job DAGs; trusted-code rootless containers; local/remote workers; Tailcat; caches/artifacts; UI/CLI/MCP; backup/restore; quotas and operating limits.

Later: hostile fork execution with stronger isolation, bounded matrices, service containers, managed image builds, reusable pipelines, deployment environments/OIDC, Windows/macOS execution, multi-controller HA, and cloud autoscaling.

No Actions YAML compatibility or marketplace/plugin runtime in v1. Inventory current workflows before migration; unsupported requirements block migration of that repository rather than being silently ignored. “Any machine” means supported Linux hardware or a suitable Linux VM; capabilities and performance depend on filesystem, kernel, architecture, and virtualization.

## 3. Architecture and dependencies

```text
GitHub webhook -> sentinel server -> durable queue / scheduler
                    |      |                 |
                 UI/API  SQLite      persistent authenticated sessions
                    |                        |
                 CLI/MCP             worker A / B / N
                    |                        |
             local object store      rootless containers
                    |                local cache + log spool
               optional S3
```

One Rust workspace, initially one `sentinel` binary with subcommands:

- `server`: API, webhook intake, scheduler, GitHub synchronization, embedded UI assets, metadata/storage maintenance.
- `worker`: executor and local store; connects to server even on the same host.
- Developer/operator CLI commands.
- `mcp`: stdio adapter using the same API. Authenticated Streamable HTTP can be served by the server.

Keep roles in separate processes/OS identities. The web server never executes repository code. A smaller worker executable can follow if distribution measurements warrant it.

Logical modules/crates: `core`, `pipeline`, `protocol`, `scheduler`, `github`, `store`, `executor`, `server`, `cli`, `mcp`; create crates when useful, not as empty scaffolding. `web/` holds new UI assets; `fixtures/` and `benchmarks/` hold reproducible workloads.

### Dependency policy

- Use maintained Rust libraries for async networking, TLS, serialization, hashing, compression, and embedded SQLite. Pin and justify dependencies.
- Required worker tooling: Git and a rootless OCI runtime. **Podman first**; Docker only after runtime conformance tests. Do not implement containers, cryptography, TLS, or Git transport ourselves.
- No required Redis, Postgres, MinIO, Elasticsearch, Kubernetes, Deno, Node server, or message broker. UI tooling can be build-time only.
- Build the application-specific storage layer ourselves; embed SQLite instead of inventing a database engine. Reconsider a custom engine only after profiling demonstrates a real bottleneck and a separate durability/recovery design exists.
- Optional Tailcat helper/self-hosted DERP and optional S3 are explicit dependencies, not hidden cloud requirements.

### Metadata

SQLite on local disk, WAL mode, foreign keys, indexed queue queries, short transactions, bounded write batching, and a dedicated blocking writer path. Keep DB I/O and CPU-heavy compression off async executor threads. Acknowledge durable intake only after commit under a documented synchronous policy.

Tables: installations, repositories, identities/roles, webhook deliveries, runs, jobs, steps, attempts, workers/sessions, leases/reservations, concurrency groups, events, GitHub outbox, cache/artifact manifests, log indexes, secret metadata, and audit records.

One active controller owns the database. No shared SQLite over NFS and no unsafe multi-active server mode. Backup recovery is v1; replicated control-plane HA is a later decision.

## 4. Fast and reliable scheduling

### Dispatch path

1. Verify webhook signature on raw body; enforce size limits.
2. Transactionally deduplicate delivery and persist intake; acknowledge promptly. Fetch pipeline/source metadata asynchronously with bounded retry.
3. Pin event identity, pipeline revision, source SHA, checkout policy, and compiled spec. Invalid configuration produces a visible failed check.
4. Persist dependency-ready jobs; immediately wake scheduler after commit.
5. Filter workers by repository access, trust pool, OS/architecture, runtime, labels, free CPU/RAM/disk, and connectivity.
6. Reserve resources and create a fenced lease transactionally; offer through an already-connected worker session.
7. Worker acknowledges, prepares workspace, executes, and emits ordered state events.
8. Completion frees capacity and wakes dependent jobs immediately; GitHub updates run asynchronously through an outbox.

Push offers over persistent bidirectional connections. A short reconciliation interval catches missed notifications. Heartbeats check liveness, not the dispatch clock. No minute-scale polling, tunnel bootstrap, or enrollment per job.

### Placement

- Weighted fair queues per installation/repo, FIFO within equal priority, aging against starvation.
- Hard resource admission first; rank eligible workers by expected start/finish, cache/image locality, disk pressure, and measured throughput.
- Cache affinity has bounded waiting; never strand jobs while another suitable worker is free.
- Backfill small jobs while reserving a path for large jobs. Enforce per-repo concurrency and operator quotas.
- No default memory overcommit. Reserve resources for host/server/spool and enforce CPU, memory, PID, and disk policy.
- Drain stops new assignments; revoke prevents future authorization/leases.
- Every queued job exposes a structured reason: `dependency`, `concurrency_limit`, `no_matching_worker`, `capacity`, `worker_offline`, `disk_pressure`, or `policy`; include missing resources/labels and age. Queue timeout is explicit.

### State and recovery

Job states: `blocked -> queued -> leased -> preparing -> running -> finalizing -> terminal`. Terminal outcomes: `passed`, `failed`, `canceled`, `timed_out`, `skipped`, `infra_failed`. Define run aggregation explicitly.

- Distinct attempt IDs and monotonic fencing generations; compare-and-set transitions reject stale completions and stale artifact/cache publication.
- Delivery is at least once. Exactly-once arbitrary shell execution is not promised. Worker dedup prevents replaying an accepted offer during a healthy session.
- Starting configurable defaults: 5-second heartbeat, 30-second lease, 5-second offer-ack timeout. Test suspension/loss/load. Worker deadlines use monotonic time with a guard margin before server expiry.
- Disconnect: spool and reconnect while lease is valid; terminate when renewal expires. Reconcile uncertain attempts before replacement. A paused process can resume late, so external side effects still require idempotency.
- Bound infrastructure retries; side-effecting jobs must opt in. Do not automatically retry ordinary test failures or uncertain deployments.
- Cancellation is durable desired state: block new starts, gracefully terminate, then kill the entire container/process group after a configured grace period.
- Cancel superseded runs within repo + event/PR/ref concurrency groups, not globally per branch string.
- Controller restart reconstructs queue/reservations and reconciles workers. Worker restart finds owned containers, kills stale ones, and resumes safe uploads without executing steps again.
- Required artifact upload failure is a finalization failure. Optional cache publication failure is a warning, not a test failure.

## 5. Worker connectivity and Tailcat

Sentinel owns enrollment, access, health, leases, and revocation. Tailcat supplies NAT-traversing transport; it is not a scheduler, mesh membership database, or authorization service.

- Worker initiates persistent mutually authenticated control connections; controller commands flow back through the session. No arbitrary inbound worker shell is needed.
- Direct TLS supports localhost/LAN/routable networks. Tailcat is an optional supported transport behind the same protocol abstraction.
- Initial adapter uses a **pinned helper process** forwarding only the Sentinel endpoint. Tailcat's upstream library is Go; do not claim native Rust integration or reimplement its WireGuard/NAT stack.
- Expiring single-use enrollment token exchanges server address/trust root. Worker generates its own key; identities are scoped, rotatable, and revocable. Application authentication remains required over Tailcat.
- Treat Tailcat addresses/key material as credentials; redact them from normal output. Loopback forwards, restricted peer identities, no `serve all`, exit-node, or unrestricted shell modes.
- Keep control independent of bulk data, with bounded transfer concurrency and priority for lease renewal/cancel. Reconnect with jitter and replay cursors.

### Fully self-hosted transport

Public Tailcat relays are rate-limited and best-effort. Support operator-owned DERP relay/map and discovery configuration avoiding mandatory Tailscale-hosted services. Document public relay reachability/certificates and the separate HTTPS ingress GitHub needs for webhooks; Tailcat does not make GitHub able to call a private endpoint.

Expose direct/relayed path, RTT, reconnects, throughput, and helper version. Relay-only connectivity works but cannot promise local-NVMe transfer speed. Prefer worker-local data.

Gate support on pinned-version tests: unattended restart, persistent identity, multiple workers, endpoint changes, NAT failure, self-hosted relay-only mode, revocation, helper crash recovery, and bounded bandwidth. Upstream currently gives no API/CLI/wire stability guarantee; compatibility tests gate upgrades.

## 6. Pipeline specification

`.sentinel.yml`, versioned strict schema, duplicate/unknown-key errors, bounded YAML size/depth/aliases, no custom tags, deterministic compiled DAG. **Proposed syntax** to finalize alongside schema in M1:

```yaml
schema: 1
on: [push, pull_request, manual]
concurrency:
  group: "${{ repo.id }}:${{ event.key }}"
  cancel_in_progress: true
jobs:
  test:
    image: rust:1-bookworm
    runs_on: {arch: amd64, labels: [linux]}
    resources: {cpu: 4, memory: 8GiB, disk: 20GiB}
    timeout: 20m
    cache:
      - name: cargo-registry
        key: "cargo-${{ hash_files('Cargo.lock') }}"
        paths: [/usr/local/cargo/registry, /usr/local/cargo/git]
      - name: cargo-target
        key: "target-${{ hash_files('Cargo.lock') }}"
        paths: [target]
    steps:
      - id: test
        run: cargo test --locked
  build:
    needs: [test]
    image: rust:1-bookworm
    resources: {cpu: 4, memory: 8GiB, disk: 20GiB}
    timeout: 20m
    steps:
      - id: build
        run: cargo build --release --locked
    artifacts:
      - name: release
        paths: [target/release/app]
        when: success
        retain: 7d
```

Specify and test:

- Push/PR/tag/manual events, branch/path filters, and explicit push/PR duplicate policy. `event.key` is stable per PR/ref and prevents unrelated cancellations.
- Jobs run in parallel when dependencies allow; steps share a job's ephemeral workspace/container environment sequentially. `needs` shares no files implicitly.
- Reject cycles, missing dependencies, duplicate IDs, invalid mount/output paths, unsatisfiable resources, and expansion beyond limits.
- Default `/bin/sh` fail-on-command-error semantics documented; Bash requires an image containing Bash. Define workdir, environment precedence, exit/signal, and cleanup behavior.
- Tiny bounded `if` grammar over event metadata/dependency outcomes, with explicit success/failure/always semantics. No arbitrary code evaluation or network access in expressions.
- `hash_files` uses pinned source, sorted paths, bounded counts/bytes, and documented no-match behavior. Server validates structure; worker reports content hashes before cache selection. Define evaluation phase for every expression.
- Resolve image tags to persisted digest/platform per run; production examples prefer digest pins. Reruns retain compiled spec and pinned inputs; new-ref dispatch is distinct.
- YAML references secret names, never values. It cannot grant itself privilege, host mounts, or a stronger trust pool.
- Artifacts specify success/failure/always retention and explicit dependent-job inputs; finalize handoff schema before migrating workflows requiring it.
- Resource defaults/maxima are server policy shown by validation. Every job has finite queue/execution timeouts.
- Publish schema, expression reference, and short Rust/Node/Python cookbooks with releases. Schema-assisted generation does not imply automatic Actions compatibility.

## 7. Execution and trust boundaries

- Rootless Podman, user namespaces, seccomp, dropped capabilities, no-new-privileges, restricted mounts, and cgroup v2 from the first runnable milestone.
- No host Docker socket or privileged-job escape hatch in v1. Image builds/deployments migrate only after a separately isolated mechanism exists.
- Separate job networks from control endpoints, host services, cloud metadata, and credentials; enforce through runtime/firewall policy.
- Checkout exact SHA with short-lived repo-scoped credentials in a worker checkout helper. Never leave tokens in URLs, job environment, Git config, or logs. Submodules/LFS need explicit support and credential scoping.
- Optional worker-local Git mirrors with locked updates, object validation, repository/trust separation, and job workspaces unable to mutate shared objects/configuration.
- PR checkout defaults to head; persist head/base SHA. A future synthetic merge policy records its actual tested SHA. Checks must identify what was tested.
- Destroy workspaces/writable clones after finalization; reconcile crash leftovers. Runtime, network, OOM, timeout, and log failures are distinct from command failures.
- Fork execution off in v1. Hostile-code support needs stronger sandboxes such as microVMs, separate pools/caches, no secrets, and restricted egress. Rootless containers share the kernel and are not a hostile multi-tenant isolation guarantee.

## 8. Sentinel-owned storage

Rust storage module and local worker data paths, not a mandatory storage service.

```text
/var/lib/sentinel/
  metadata.sqlite
  objects/<digest-prefix>/<digest>
  logs/<run>/<job>/<attempt>/<segment>
  manifests/
  tmp/
/var/lib/sentinel-worker/
  state.sqlite
  spool/<attempt>/
  workspaces/<attempt>/
  cache/<scope>/<entry>/
  mirrors/<repository-id>/
```

### Durability, quotas, and recovery

- Immutable checksummed objects and versioned manifests. Authorize logical IDs; never expose arbitrary filesystem paths.
- Stream to temp, verify length/digest, flush file, same-filesystem atomic rename, flush directory, then commit reference. A crash may leave an orphan, never a published incomplete object.
- Idempotent resumable uploads, bounded chunks/concurrency, committed-only reads, orphan cleanup, and integrity reconciliation. Defend traversal/symlink escapes during export/extraction.
- Controller disk is default durable log/artifact destination. Workers retain spools until acknowledged. Local caches are disposable; remote replication optional.
- Persist log completeness/finalization. Worker-disk loss may lose unacknowledged bytes; report gaps. Document/test the exact durability acknowledgement boundary.
- Quotas per installation/repo/run plus global high/low watermarks and reserved metadata/spool space. Stop admission before disk exhaustion.
- Proposed configurable defaults: logs 14 days, artifacts 7 days, byte-capped LRU caches. Define actual byte caps during hardware inventory.
- GC respects active readers/uploads/jobs/cache leases. Manifest deletion and object reclamation are separate stages; never delete mounted data.
- Online SQLite backup plus consistent manifest/object snapshot, migrations, integrity checks, restore drills, and upgrade/rollback guide. Back up secret encryption keys separately and restore matching metadata/objects.

### Local-first cache

1. Immutable worker-local entries with writable per-job clones and atomic success publication.
2. Reflinks where supported; benchmark btrfs snapshots for large directory trees before declaring that optimized backend supported.
3. Ordinary filesystems use safe bounded copies and report backend/cost. Never writable hardlinks. ZFS/overlay-specific backends wait for evidence/conformance tests.
4. Scope keys by installation/repo ID, trust class, architecture, image/toolchain identity, format version, and user key. PR writes cannot poison protected-branch caches; downward sharing requires explicit policy and secret-free content.
5. Concurrent writers produce distinct immutable generations; choose winners transactionally. Corrupt/incompatible/missing cache is a miss, not build failure.
6. Scheduler prefers local copies. Cross-worker hydration uses portable manifests and checksummed compressed transfer; local snapshot mounts do not work across hosts by magic.
7. Begin with simple versioned object transfer. Add chunk dedup only if measurements justify it. Filesystem send/receive can be an optional same-backend optimization, not the portable protocol.
8. Report hit/miss/partial, bytes, backend, key dimensions, and miss reason. Evaluate compiler caches later; a lockfile alone does not capture all compiler inputs.

### External S3 option

Adapter for immutable artifacts/log segments and optional portable cache exports; SQLite metadata stays local. Configurable endpoint/region/bucket/prefix, TLS, scoped credentials, streaming/multipart, checksums, retries/abort cleanup, range reads, and named compatibility tests.

On S3 outage retain bounded spool and expose degraded durability; enforce admission/finalization policy when full. Cache upload may degrade to a miss; required artifact persistence cannot silently disappear. No MinIO dependency and no goal of implementing an S3 server.

## 9. Logs and agent diagnostics

### Capture once, present two ways

- Bounded stdout/stderr frames: run/job/step/attempt IDs, sequence, timestamp, stream, and byte/line offsets. Preserve per-source order, not fictional exact ordering across streams.
- Redact before storage/index/transport/UI. Handle secrets split across reads, long lines, invalid UTF-8, ANSI, and binary output. Arbitrary transformations of secrets cannot be reliably redacted.
- Segmented append logs with sparse step/time/line indexes; compress sealed segments and stream active ones. No per-line SQLite writes or whole-file reads to obtain tails.
- Bounded memory queues and worker disk spool isolate execution from slow consumers. Resume by cursor. At output caps, keep draining pipes, emit explicit truncation/gap events, and mark completeness; no unbounded RAM or silent loss.
- Initial diagnostic inputs: versioned Sentinel events, Rust compiler JSON, JUnit reports. Bound parser size/time and treat all content as untrusted. Plain commands still expose exit/signal/OOM/timeout and selected excerpts.

### Failure API contract

`get_failure`: status/failure class, failed command/step, exit/signal, parsed message/file/line/test when available, relevant contextual excerpts, resource/cache/timing clues, and stable evidence references. Select the actual compiler/test error rather than only the final lines; include fallback tail when parsing fails.

Default budget **8 KiB text / 20 diagnostics**, configurable hard ceiling **64 KiB**. Responses include schema version, `truncated`, `next_cursor` where applicable, `log_complete`, and omitted counts when known. Bytes are enforceable; token estimates are advisory.

Log queries: step/attempt, cursors, literal search, context, line/byte budget, incremental `since`. Regex later only with bounded non-backtracking execution. Deterministic summaries require no model API or token bill. Optional future model summaries cite evidence and cannot replace logs or determine outcomes.

MCP labels logs/repository content as untrusted data, never agent instructions. Inferred root causes are labeled as inference.

## 10. API, CLI, MCP, and UI

Shared versioned API/authorization, stable IDs, pagination, structured errors, request IDs, mutation idempotency, and resumable event cursors. Publish OpenAPI/schema artifacts. SSE is sufficient for browser updates; workers need bidirectional sessions.

```text
sentinel auth login
sentinel status --repo owner/repo --sha <sha> --json
sentinel runs list
sentinel run <id>
sentinel wait <id> --timeout 10m --json
sentinel failure <id> --max-bytes 8192 --json
sentinel logs <id> --step test --follow
sentinel logs <id> --search error --context 5 --max-bytes 8192
sentinel dispatch --repo owner/repo --ref main
sentinel rerun <id>
sentinel cancel <id>
sentinel pipeline validate
sentinel pipeline explain
sentinel workers list
sentinel queue explain <job-id>
sentinel cache list
sentinel artifact get <run-id> <artifact-name>
sentinel doctor
```

CLI: human default, JSON/NDJSON, documented exit codes distinguishing failed run/pending/transport error. Bounded event-driven `wait` avoids agent polling loops. `doctor` diagnoses runtime/filesystem/cgroups/connectivity/disk/GitHub without credentials. Linux/macOS/Windows CLI even though execution is Linux-first.

MCP read tools: `list_runs`, `get_run`, `wait_run`, `get_failure`, `get_logs`, `explain_queue`, `get_pipeline`, `validate_pipeline`; schema/cookbook/expressions as resources. Mutations: `dispatch`, `rerun`, `cancel` with scopes, idempotency, audit, and accurate MCP tool annotations. A confirmation boolean is not authorization. No repo editing/Git push/secret administration tool.

Stdio uses CLI credentials. Streamable HTTP uses supported MCP authorization and origin/session handling, verified against target clients. Both share bounded diagnostics and repository authorization.

### New human UI

Serve lightweight build-time UI assets from Rust; choose stack after accessible live-log prototype. Browser interaction need not be Rust/WASM to obtain a fast Rust backend.

- Runs by installation/repo/branch/PR/SHA, queue/execute timings, cache effectiveness.
- Failure summary first, file/test evidence links, job DAG, step timelines.
- Virtualized logs, folded successes, contextual search, stable links, reconnect cursors, visible gaps/truncation.
- Worker capacities/reservations, labels, drain/offline, disk backend/pressure, direct/relayed path.
- Queue explanations, cache miss reasons, artifacts, cancel/rerun, GitHub sync lag.
- Keyboard accessibility, contrast/status labels, responsive layout, bounded DOM/memory.
- Built-in counters/histograms and scrapeable metrics; external observability optional.

## 11. GitHub and authorization

- Org/personal GitHub App installations with selected repos. Store immutable IDs; handle install removal/suspension, repo access change/rename/transfer.
- Base permissions: contents read, checks write, pull requests read, metadata read. Org members read only for org-membership policies; personal installations use owner/collaborator or explicit grants. Additional features request only necessary permissions.
- Separate human login and installation credentials. Repository reader/operator/admin roles, periodic revalidation/revocation; org membership need not grant all mutations.
- Short-lived scoped checkout tokens; no classic PAT in the normal path. Hashed CLI tokens, expiring sessions, encrypted secret values with key outside SQLite, rotation, CSRF protection, and audit.
- Durable dedup/outbox retries, rate-limit/backoff, missed-delivery and pending-check reconciliation after outages. Accepted work dispatch is independent of Checks latency.
- Subscribe to push, relevant PR actions, check rerequests, installation/repo-access events. Explicit draft/filter policy; duplicates/reordering handled.
- Per-job checks `sentinel / <job>` plus stable aggregate required check `sentinel / ci`. Invalid config/required failures fail aggregate. Define skipped-job/filter semantics so required checks do not remain pending forever.
- Map outcomes to GitHub conclusions with `details_url`; persist external check IDs/attempts. Reconcile ambiguous API timeouts before creating duplicates. Verify `gh pr checks` and rerequests end-to-end.
- Correct commit/PR association; test stale completions, new pushes, deleted refs, reruns, and checkout policy. `merge_group` support is mandatory before migrating repos using merge queues.
- GitHub outages can block intake/source fetch; explain that separately from worker capacity. Migrated execution/artifacts do not consume Actions usage, but GitHub limits and unrelated workflows still exist.

## 12. Performance targets and evidence

Targets, **not measured results**. Reference: Linux modern 8-core host, 32 GiB RAM, NVMe, supported rootless runtime, controller/worker RTT <= 10 ms, warm image/source/cache, eligible idle capacity. Publish exact hardware/kernel/filesystem/runtime/revision.

| Metric | Initial target |
|---|---|
| Durable webhook ACK, excluding GitHub delivery | p95 < 250 ms |
| Dependency-ready + available capacity -> worker offer | p95 < 100 ms; p99 < 250 ms |
| Offer -> ack, connected LAN worker | p95 < 100 ms |
| Ready -> first user process, warm reference fixture | p95 < 2 s; p99 < 5 s |
| Local optimized cache preparation, published fixed fixture | p95 < 500 ms; report bytes/file count/backend |
| Log capture -> UI/CLI on LAN | p95 < 250 ms |
| Cancel -> termination, healthy connection | p95 < 2 s excluding configured grace |
| Indexed failure query on 100 MiB run | p95 < 200 ms; <= 8 KiB response |
| Idle server / worker RSS excluding runtime/jobs | provisional < 150 / 75 MiB |
| Combined idle control CPU | provisional < 1% of one core |

Measure delivery, intake/config, dependency wait, capacity wait, dispatch, checkout, image pull, cache restore, container setup, each step, cache commit, artifact upload, log flush, and Checks propagation. Include total push-to-feedback; fast dispatch alone is insufficient.

Benchmark matrix:

- No-op, Rust clean/small-edit build, Node install/tests, many tiny files, large artifacts, noisy 100 MiB logs, 10 GiB caches with published file distributions.
- Fully cold, image/source/dependency/compiler warm, exact hit/miss/invalidation/corruption; report bytes and latency.
- Same-host direct runtime, healthy GitHub self-hosted runner, Woodpecker, Sentinel. Equal resources, commands, image/source, isolation, warm state.
- Hosted Blacksmith comparison only if available; disclose hardware/network differences. Vendor multipliers are not Sentinel evidence.
- Fleet 1/3/10, bursts 1/10/100; correctness/load target 100 workers and 10,000 queued jobs. Report p50/p95/p99/max wait/throughput/CPU/RSS/I/O/failure rate. Saturated queue wait is not subject to idle-capacity SLO.
- LAN, Tailcat direct/relay, injected latency/loss, slow/full disk, controller/worker restart, stale lease, missed webhook, S3 outage.
- Repeated trials with sample counts/variance and raw results. Fixed-hardware regression gate initially 10% p95 overhead regression, accounting for noise.

Profile before custom allocators, mmap everywhere, io_uring, bespoke indexes, dedup, or warm microVM pools. Optimize measured bottlenecks. Warm pools never retain writable job state or secrets between jobs.

## 13. Milestones and release gates

### M0 — Preserve legacy and validate design

- Rename original `main` to `legacy`; new fresh-history `main` starts with plan/README/MIT/ignore rules and becomes default. Preserve original commit/history without force-push.
- Inventory org/personal workflows: languages/images/services/matrices/artifacts/secrets/deployments/merge queues/required checks/cross-job inputs.
- Capture actual-machine baselines and capabilities. Spike pinned Tailcat direct/relay, rootless cgroups, SQLite dispatch, cache cloning. Resolve schema/protocol through short ADRs.

Gate: history verified, prerequisites and migration blockers documented, benchmark harness and core decisions agreed. No guessed calendar promises.

### M1 — Durable single-host vertical slice

- Rust server/worker, SQLite migrations, authenticated enrollment/session, strict basic schema, manual dispatch, one App repo, exact checkout, isolated container, spool, Checks outbox.
- Leases/reservations/timeouts/cancel/dedup/restart reconciliation from the start; CLI status/logs and minimal new run UI.

Gate: real PR green/red; duplicate delivery creates no duplicate logical run; restart/cancel tests pass; server never executes jobs. No cache required yet.

### M2 — Fleet and queue reliability

- DAG, fairness/aging, per-repo concurrency, superseded cancel, labels/resources, drain/revoke, queue explanations, org/personal installations.
- Direct/Tailcat sessions, owned relay documentation, fenced reconnect, bounded control/bulk paths.

Gate: three workers load-balance bursts within allocations; eligible idle capacity is used promptly; stale completions cannot replace current state; relay/partition/restart tests pass.

### M3 — Locality and storage

- Immutable caches/safe copy/optimized backend; artifacts and DAG handoff; segmented indexes; quotas/retention/GC/restore.
- Portable remote hydration and optional S3 tested for interruption/corruption.

Gate: measured warm improvement; no concurrent cache corruption or lower-trust poisoning; disk-pressure/restore drills pass; log/artifact completeness is truthful.

### M4 — Agent and human experience

- Bounded failure evidence, Rust/JUnit parsing, cursor search, JSON/wait CLI, MCP stdio/HTTP and docs.
- Accessible virtualized UI, worker/queue/cache pages, GitHub rerequest/stable required-check semantics.

Gate: agent locates actual error in noisy 100 MiB fixture using bounded responses, retrieves evidence, and reruns without full dumps; human can find same error/queue reason; authorization/parser-limit tests pass.

### M5 — Pilot, benchmark, replace

- Shadow representative repos while old CI remains authoritative; compare results, filters, secrets, artifacts, merge behavior, latency.
- Publish evidence/limitations; meet reference targets and scale/fault tests.
- Change required checks repo by repo after parity; disable superseded Actions to stop duplicate execution. Preserve explicit rollback to old workflows/required checks.
- Tag v0.1 with Linux packages/systemd/container examples, upgrade/backup/recovery docs, dependency/license inventory.

Gate: migrated repos run entirely under Sentinel; org/personal installs and remote workers work; storage is ours; no hosted Sentinel account needed; claims match benchmarks.

## 14. Decisions and open questions

Adopted: Rust core; independent pipelines; existing repo with preserved legacy; new UI; Linux-first fleet; durable push scheduling; local-first caches; SQLite; owned file storage; optional S3; pinned Tailcat plus direct TLS; shared API; deterministic bounded diagnostics; MIT/no usage gate.

Resolve through hardware/workflow evidence:

1. Actual worker CPU/RAM/filesystems/cgroups/RTT and relay host.
2. Repos blocked by services, matrices, image publishing, deployments, merge queues, forks.
3. Optimized cache backend and byte/retention defaults.
4. UI stack and measured binary/RSS limits.
5. Tailcat pin/upgrade policy, wire framing, bulk concurrency.
6. Key backup, recovery-point/recovery-time goals, and S3-outage policy.

These gates do not defer scheduling correctness or multi-host design until after v1.

## 15. Sources and verification notes

Inspected 2026-09-13; pin versions and recheck exact behavior during implementation.

- [Legacy reviewed commit](https://github.com/RusticStack/sentinel/tree/ba6c583715c16fde498d646577c98bc60c221adb): README/tree/`lib/github.ts`/`lib/realtime.ts`/LICENSE through GitHub API.
- [Blacksmith](https://www.blacksmith.sh/): vendor emphasizes fast hardware, colocated caches, persistent NVMe layers, microVM startup, and observability. Vendor claims are not independent benchmarks.
- [Tailcat README/source](https://github.com/tailscale/tailcat): Go CLI/library, account-free NAT transport, owned DERP, keys/forwarding, explicit instability; read through GitHub API. Integration has not been tested yet.
- [GitHub branch rename](https://docs.github.com/en/rest/branches/branches#rename-a-branch): consulted through Context7; appropriate permissions required and completion may be asynchronous.
- Implementation verification references to recheck at corresponding milestones: [Checks](https://docs.github.com/en/rest/checks/runs), [webhooks](https://docs.github.com/en/webhooks/webhook-events-and-payloads), [SQLite WAL](https://www.sqlite.org/wal.html), [backup](https://www.sqlite.org/backup.html), [Woodpecker](https://woodpecker-ci.org/docs/intro), [MCP specification](https://modelcontextprotocol.io/specification/latest). This plan is not an implementation conformance report.
