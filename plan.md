# Sentinel — implementation plan

Status (2026-10-24): design reference and acceptance criteria, rebaselined against the current tree. [TODO.md](TODO.md) is the execution tracker: it records current task states, historical evidence and open work. **v0.1** is Parts 00–15 and 24, including Q11–Q13 host enrollment/placement and the B11 Blacksmith gate. Part 24 starts now; it closes after the remaining correctness work, Part 14, Q13, B09 and B11. Part 15's V01/V02 packaging baseline happens earlier, while V05/V06 release qualification waits for Part 24. The already-landed Linux microVM/runtime-routing code is reconciled in Part 23 rather than treated as absent. **After v0.1** (M6), unless separately promoted: GitHub Actions runner mode (Part 25), Windows jobs (Part 17), artifacts (Part 18), tenant storage limits (Part 19), the TanStack Start interface (Part 20), guided migration (Part 21) and AI assistance (Part 22). Repository: `RusticStack/sentinel`.

Statements below are decisions, constraints and targets; where the code or a topical document under [`docs/`](docs/) differs, that document is the contract and this plan is stale.

## 1. Product contract

Build a fully open-source, self-hosted CI engine optimized for fast feedback on organization **and personal** Git repositories, including self-hosted Gitea, Forgejo, GitLab and bare repositories. GitHub is the first native forge integration, with required PR Checks; other forges initially use generic Git intake and Sentinel UI/API results. Sentinel owns execution, scheduling, logs, caches, artifacts, and diagnostics. Borrow Woodpecker's independent-server/runner model and Blacksmith's emphasis on fast startup, local data, and observability.

- Rust control plane, worker, storage modules, CLI, and MCP integration.
- One controller host to start; multiple heterogeneous workers are a v1 requirement. Only the main deployment needs the UI and controller extras. A platform administrator adds a worker through a UI-generated, worker-only shell bootstrap that connects over Tailcat by default, with direct TLS as fallback. Each worker runs jobs in the strongest verified sandbox its host supports: rootless Podman without KVM; Firecracker for Linux and, after its M6 promotion, Cloud Hypervisor for Windows with KVM ([16.8](#168-microvm-execution-on-kvm-hosts)).
- One deployment supports multiple organizations and personal namespaces, with authenticated users, deployment super admins, controlled registrations, and tenant-scoped resources from v1.
- Three open-source workload families — GitHub CLI (Go), ripgrep (Rust) and gson (Java/Maven) — are the representative performance/migration workloads, not the architecture specification. Maintainer-controlled mirrors or forks adapt their orchestration to Sentinel; requirements that fundamentally change Sentinel remain repository-side adaptations or external lanes. Full workflow parity is not a release gate. See [pilot workloads](docs/pilot-repositories.md).
- Primary relative performance objective (B11): trigger-to-required-check **p95 at most half of Blacksmith's p95 for the same checks and conditions**, preserving every assertion and freshness rule. Keep the independent absolute objective (B08): take a representative warm PR workload from five minutes or more to **under one minute on the same hardware**. Optimize useful end-to-end feedback, not queue latency or startup alone. See [performance research and engineering strategy](docs/performance-research.md).
- No Sentinel execution-minute pricing, license server, mandatory cloud account, or paid feature gates. Hardware, electricity, bandwidth, optional S3, and GitHub service limits still exist. Capacity and retention limits prevent unattended machines from filling up.
- Near-immediate dispatch when an eligible worker has capacity; explicit explanations when it cannot start. Controller-approved CPU/RAM/storage ceilings apply once per physical host; placement is fastest-eligible by default, with a deterministic operator host-priority override after hard admission.
- Two ways in: native `.sentinel.yml` pipelines, the full-speed mode with Sentinel's own scheduling, caches, logs, diagnostics and Checks; and, after v0.1, a GitHub Actions runner mode in which GitHub orchestrates and a repository migrates by changing `runs-on:` ([16.10](#1610-github-actions-runner-mode)).
- Human-readable web UI and bounded, structured, evidence-linked responses for coding agents.
- MIT licensing, public build instructions, protocol/schema documentation, dependency licenses, and reproducible benchmark recipes.

**Performance is an engineering target, not a language guarantee.** Rust gives control over allocation, concurrency, memory, and I/O. It does not make compilation, slow disks, cold image pulls, or WAN links inherently faster. “Fastest on the market” is an ambition to validate with published measurements, not an initial product claim.

## 2. Decisions against the original plan

| Original assumption | Decision |
|---|---|
| One queue, slots on one VPS | Durable event-driven fleet scheduler with resource reservations and fairness |
| Reuse/fork the Fresh UI | New UI (Nuxt 4 today, moving to TanStack Start, [16.4](#164-web-interface-on-tanstack-start)); the old implementation is reference material |
| Go or Rust; four mandatory processes | Rust workspace; server embeds storage; workers remain separate execution boundaries; the optional web interface is its own Node process |
| Dropping Actions guarantees speed | Measure dispatch, preparation, execution, transfer, and total feedback independently |
| Migrating means rewriting CI | Runner mode: change `runs-on:`, keep the workflows; native pipelines are the optional full-speed path ([16.10](#1610-github-actions-runner-mode)) |
| One sandbox for every host | Runtime by host: rootless Podman without KVM; Firecracker (Linux) and Cloud Hypervisor (Windows) microVMs with KVM; no QEMU ([16.8](#168-microvm-execution-on-kvm-hosts)) |
| Cache is always a snapshot mount | Local CoW fast path plus ordinary-filesystem and remote-transfer paths |
| Hardlink clone is a snapshot substitute | Never hardlink writable jobs into shared caches; writes corrupt other jobs |
| Lockfile-only cache keys | Include trust scope, architecture, image/toolchain identity, and format version |
| Tailed logs are sufficient for AI | Structured diagnostics, contextual excerpts, budgets, cursors, evidence links |
| Concurrency/cancellation/isolation come last | Required before running real repository code |
| SQLite/Postgres/store service undecided | Embedded SQLite metadata; Sentinel-owned file store; optional S3 adapter |
| Fixed week estimates | Evidence-based milestones and release gates |

### Legacy dashboard

The `legacy` branch holds a Deno 2 / Fresh monitoring dashboard (GitHub OAuth, one-organization membership gate, Deno KV sessions, Actions runner and run views polled every 15-30 s). It is monitoring, not execution or scheduling, and its single-organization auth does not fit personal namespaces, so only its navigation and deployment lessons carry over. It does not explain why GitHub-hosted runner waits last hours; Sentinel must expose labels, concurrency, connectivity and dispatch conditions rather than inherit opaque waits.

### Scope boundaries

v0.1 (V1): Linux x86_64/arm64 controller/workers; provider-independent Git repository connections with manual/generic hook/opt-in polling intake; multiple org/personal GitHub App installations and native PR Checks; authentication and super-admin registrations; OAuth CLI/HTTP MCP; CLI-managed secrets; own YAML and job DAGs; verified trusted-code sandboxes (no network by default, operator-granted egress per worker); local/remote workers through Q11's UI-generated Tailcat enrollment with direct-TLS fallback; Q12 host ceilings/priority and Q13 fleet verification; first-class caches/artifacts; UI/CLI/MCP only on the main deployment; backup/restore; quotas and operating limits; B09 and B11 evidence. The Linux microVM path is included only to the extent M01–M06/M08 verify it. Gitea/Forgejo/GitLab native webhooks, PR/MR metadata, sign-in and status adapters are deferred; generic Git operation needs no GitHub account. This is a purpose-built CI engine with specialized scheduling, storage, caching and diagnostics, not a general automation platform. Different project toolchains run through images/commands without repository-specific scheduler rules.

Incremental general features: named pipelines, schedules/typed inputs, multi-repository checkout, outputs/finalizers, and conservative declared-input result reuse. Add only with a small general contract and measured value. Planned after v0.1, in section 16: runner mode, Windows jobs, artifact and storage-limit breadth, the TanStack Start interface, guided migration and AI assistance. The Linux microVM implementation landed early and has its required verification pulled into v0.1; it remains the boundary hostile forks need. Optional, by measured need: Docker/Compose compatibility environment, generic matrix expansion, declarative service containers, reusable pipelines, deployment environments/OIDC, multi-controller HA and cloud autoscaling. Image builds and registry publishing can be repository commands on compatible authorized workers; no mandatory built-in release engine or VM fleet.

Sentinel never interprets Actions YAML: in runner mode the official `actions/runner` does, inside Sentinel's sandboxes; native Actions-syntax execution and a marketplace/plugin runtime are not in scope. Inventory current workflows before migration; unsupported requirements block migration of that repository rather than being silently ignored. “Any machine” means supported Linux hardware or a suitable Linux VM (Windows hosts after v0.1); capabilities and performance depend on filesystem, kernel, architecture, and virtualization.

## 3. Architecture and dependencies

```text
Git/API/hook/poll ----> sentinel server -> durable queue / scheduler
GitHub workflow_job --/    |      |                 |
                        UI/API  SQLite      persistent authenticated sessions
                           |                        |
                        CLI/MCP             worker A / B / N
                           |                        |
                    local object store      sandbox per attempt: rootless Podman,
                           |                or Firecracker / Cloud Hypervisor microVM
                      optional S3           local cache + artifact store + log spool
```

One Rust workspace, initially one `sentinel` binary with subcommands:

- `server`: API, generic Git and forge event intake (after v0.1 also GitHub `workflow_job` demand for runner mode), bounded source/pipeline resolution and opt-in ref polling, scheduler, GitHub synchronization, metadata/storage maintenance.
- `sentinel-web` (optional, Node): the human web interface in front of the API ([web interface](docs/web-ui.md)).
- `sentinel-ai` (after v0.1, optional, Node): advisory AI analyses through the API on Effect 4, OpenRouter by default, never on a check's path ([16.6](#166-ai-assistance)).
- `worker`: executor and local store; connects to the one active controller even on the same host. It detects its host's sandbox and advertises it. Q11 installs only this role through a UI-generated bootstrap; workers do not run the controller, UI, MCP or other main-host extras. It applies controller-approved host ceilings and cannot raise its own priority. In runner mode it starts the official GitHub runner inside that sandbox and serves the runner's cache and artifact traffic from its local stores.
- Developer, operator and agent CLI commands.
- `mcp`: stdio adapter using the same API. Authenticated Streamable HTTP is served by the server.

Keep roles in separate processes/OS identities. The web server never executes repository code. A smaller worker executable can follow if distribution measurements warrant it.

Crates are split by boundary and created when useful, not as empty scaffolding; the current set is in the [AGENTS.md](AGENTS.md#layout) layout table. `web/` holds the web interface (Nuxt 4 today, being replaced by TanStack Start, [16.4](#164-web-interface-on-tanstack-start)); `fixtures/` and `bench/` hold reproducible workloads and records.

### Dependency policy

- Use maintained Rust libraries for async networking, TLS, serialization, hashing, compression, and embedded SQLite. Pin and justify dependencies.
- Required worker tooling: Git and a rootless OCI runtime. **Podman first**; Docker only after runtime conformance tests. On a KVM host, after v0.1, a VMM: Firecracker for Linux guests and Cloud Hypervisor for Windows guests ([16.8](#168-microvm-execution-on-kvm-hosts)). Do not implement containers, cryptography, TLS, or Git transport ourselves.
- Project tools (Go, Rust, Python, Java, Node, Bun, pnpm, Gradle, Bazel, compilers, browsers, builders) belong in project-selected versioned images/scripts. Cookbook profiles expose cache paths and diagnostics, not privileged plugins. Optional runtime capabilities must be justified across workloads; one repository's Docker or emulation harness does not mandate VM lifecycle support in Sentinel.
- No required Redis, Postgres, MinIO, Elasticsearch, Kubernetes, Deno, or message broker. The web interface is an optional Node process (`sentinel-web`; Nuxt 4 now, TanStack Start next): the owner chose a full-stack interface over build-time-only assets for its components, server rendering and maintainability; the controller, CLI and MCP never need it. It holds no credential and no state. `sentinel-ai` is the same kind of optional Node process.
- Build the application-specific storage layer ourselves; embed SQLite instead of inventing a database engine. Reconsider a custom engine only after profiling demonstrates a real bottleneck and a separate durability/recovery design exists.
- Optional Tailcat helper/self-hosted DERP and optional S3 are explicit dependencies, not hidden cloud requirements.

### Metadata

SQLite on local disk, WAL mode, foreign keys, indexed queue queries, short transactions, bounded write batching, and a dedicated blocking writer path. Keep DB I/O and CPU-heavy compression off async executor threads. Acknowledge durable intake only after commit under a documented synchronous policy.

Tables: tenants/namespaces, users, external identities, memberships/roles, registrations/invitations, sessions, service accounts/tokens, installations and tenant bindings, repositories, schedules, webhook deliveries, runs, jobs, steps, attempts, workers/pool grants, leases/reservations, concurrency/resource locks, events, GitHub outbox, cache/artifact manifests, log indexes, secret metadata, and audit records. All tenant-owned rows carry a tenant ID; use composite ownership constraints/indexes and centralized scoped queries.

One active controller owns the database. No shared SQLite over NFS and no unsafe multi-active server mode. Backup recovery is v1; replicated control-plane HA is a later decision.

## 4. Fast and reliable scheduling

### Dispatch path

1. Authenticate and authorize the trigger against its tenant-owned repository; verify GitHub webhook signatures on the raw body and enforce size limits. Manual dispatch, generic ref-update events, optional ref polling and (runner mode) GitHub `workflow_job` `queued` events share intake with forge adapters.
2. Transactionally deduplicate delivery and persist intake; acknowledge promptly. Fetch pipeline/source metadata asynchronously with bounded retry.
3. Pin event identity, pipeline revision, source SHA, checkout policy, and compiled spec. Invalid configuration produces a visible Sentinel failure and, for GitHub-associated work, a failed check. A runner-mode event compiles to a one-step job of its label's resource class whose step is the GitHub runner; GitHub, not Sentinel, resolves the workflow.
4. Persist dependency-ready jobs; immediately wake scheduler after commit.
5. Filter workers by repository access, trust pool, OS/architecture, isolation (container or microVM), labels (including `egress`), free CPU/RAM/disk, and connectivity.
6. Reserve resources and create a fenced lease transactionally; offer through an already-connected worker session.
7. Worker acknowledges, prepares workspace, executes, and emits ordered state events.
8. Completion frees capacity and wakes dependent jobs immediately; GitHub updates run asynchronously through an outbox.

Push offers over persistent bidirectional connections. A short reconciliation interval catches missed notifications. Heartbeats check liveness, not the dispatch clock. No minute-scale polling, tunnel bootstrap, or enrollment per job.

### Placement

- Weighted fair queues per installation/repo, FIFO within equal priority, aging against starvation.
- Fairness is hierarchical: tenant -> repository -> priority/FIFO. Enforce tenant capacity budgets across all its installations. Shared pools require explicit grants; reserve capacity for PR feedback so a long manual production run cannot consume the last eligible PR worker. Host priority is a separate controller-owned placement policy, never a tenant-controlled fair-queue or worker-advertised field.
- Hard tenant/pool/architecture/OS/isolation/label/resource admission first. Rank eligible workers by measured expected finish using host throughput, held load, cache/image locality and disk pressure. Fastest eligible is the default; an explicit deterministic operator host-priority policy may override speed only after admission and cannot make an ineligible worker eligible.
- Cache affinity has bounded waiting; never strand jobs while another suitable worker is free.
- Backfill small jobs while reserving a path for large jobs. Enforce per-repo concurrency and operator quotas.
- No default memory overcommit. Controller-approved CPU/RAM/storage ceilings apply once per physical `host_id`, across every worker identity, and cover workspaces, caches, mirrors, images and spools. Reserve resources for host/server/spool and enforce CPU, memory, PID and disk policy. Admission without a total per-job byte quota is not called hard storage enforcement. A cap reduction stops new oversubscription without silently killing accepted work.
- Drain stops new assignments; revoke prevents future authorization/leases.
- Every queued job exposes a structured reason: `dependency`, `concurrency_limit`, `no_matching_worker`, `capacity`, `worker_offline`, `disk_pressure`, or `policy`; include missing resources/labels and age. Queue timeout is explicit.

### State and recovery

Job states: `blocked -> queued -> leased -> preparing -> running -> finalizing -> terminal`. Terminal outcomes: `passed`, `failed`, `canceled`, `timed_out`, `skipped`, `infra_failed`. Define run aggregation explicitly.

- Distinct attempt IDs and monotonic fencing generations; compare-and-set transitions reject stale completions and stale artifact/cache publication.
- Delivery is at least once. Exactly-once arbitrary shell execution is not promised. Worker dedup prevents replaying an accepted offer during a healthy session.
- Defaults: 5-second heartbeat, 30-second lease, 5-second offer-ack timeout ([worker link](docs/worker-link.md)). Worker deadlines use monotonic time with a guard margin before server expiry.
- Disconnect: spool and reconnect while lease is valid; terminate when renewal expires. Reconcile uncertain attempts before replacement. A paused process can resume late, so external side effects still require idempotency.
- Bound infrastructure retries; side-effecting jobs must opt in. Do not automatically retry ordinary test failures or uncertain deployments.
- Cancellation is durable desired state: block new starts, gracefully terminate, then kill the entire container/process group (or VM) after a configured grace period. A committed cancel is pushed to the session holding the attempt (worker protocol 11), and the heartbeat still carries every pending cancel ([worker link](docs/worker-link.md#pushed-cancellation-protocol-11)). In runner mode GitHub's own cancel ends the runner; a Sentinel cancel or lease loss destroys the sandbox.
- Cancel superseded runs within repo + event/PR/ref concurrency groups, not globally per branch string.
- Concurrency groups also include tenant and named pipeline; distinct acceptance/focus pipelines can request a shared tenant-scoped resource lock for a fixed-port environment. Resource locks carry leases/fencing and cleanup requirements independently of supersession cancellation.
- Controller restart reconstructs queue/reservations and reconciles workers. Worker restart finds owned containers, kills stale ones, and resumes safe uploads without executing steps again.
- Required artifact upload failure is a finalization failure. Optional cache publication failure is a warning, not a test failure.

## 5. Worker connectivity and Tailcat

Sentinel owns enrollment, access, health, leases, and revocation. Tailcat supplies NAT-traversing transport; it is not a scheduler, mesh membership database, or authorization service.

- Worker initiates persistent mutually authenticated control connections; controller commands flow back through the session. No arbitrary inbound worker shell is needed.
- Direct TLS supports localhost/LAN/routable networks. Tailcat is the default transport generated by Q11 and remains an optional transport behind the same protocol abstraction; direct TLS is the supported fallback.
- Initial adapter uses a **pinned helper process** forwarding only the Sentinel endpoint. Tailcat's upstream library is Go; do not claim native Rust integration or reimplement its WireGuard/NAT stack.
- Q11's UI-generated worker-only shell bootstrap installs pinned binaries and verifies their digests before execution; it is downloadable/copyable, not an uninspected remote response piped into a shell. A short-lived, single-use, pool-bound enrollment carries server address/trust and the controller-approved host policy. The worker generates its TLS and Tailcat identities locally, and the authenticated enrollment authorizes both identities atomically. Identities are scoped, rotatable and revocable. Application authentication remains required over Tailcat.
- Enrollment secrets never appear in URLs, process arguments, logs or persistent script text. Treat Tailcat addresses/key material as credentials; redact them from normal output. Loopback forwards, restricted peer identities, no `serve all`, exit-node, or unrestricted shell modes. Include uninstall/rollback and visible refusal of unsupported hosts.
- Keep control independent of bulk data, with bounded transfer concurrency and priority for lease renewal/cancel. Reconnect with jitter and replay cursors.

### Fully self-hosted transport

Public Tailcat relays are rate-limited and best-effort. Support operator-owned DERP relay/map and discovery configuration avoiding mandatory Tailscale-hosted services. Document public relay reachability/certificates and the separate HTTPS ingress GitHub needs for webhooks; Tailcat does not make GitHub able to call a private endpoint.

Expose direct/relayed path, RTT, reconnects, throughput, and helper version. Relay-only connectivity works but cannot promise local-NVMe transfer speed. Prefer worker-local data.

Gate support on pinned-version tests: unattended restart, persistent identity, multiple workers, endpoint changes, NAT failure, self-hosted relay-only mode, revocation, helper crash recovery, and bounded bandwidth. Upstream currently gives no API/CLI/wire stability guarantee; compatibility tests gate upgrades.

## 6. Pipeline specification

`.sentinel.yml`, versioned strict schema, duplicate/unknown-key errors, bounded YAML size/depth/aliases, no custom tags, deterministic compiled DAG. The authoritative syntax and limits are in [pipeline schema](docs/pipeline-schema.md); this example shows the shape. It is a single default pipeline. Named pipelines can later express independent triggers/inputs/concurrency/required status without copying Actions; no repository's workflow names are built-in Sentinel concepts, and unsupported lanes keep their existing executor until adapted.

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

The pipeline contract covers:

- Push/PR/tag/manual events, branch/path filters, and explicit push/PR duplicate policy. `event.key` is stable per PR/ref and prevents unrelated cancellations.
- Durable UTC cron schedules with unique scheduled-occurrence IDs, overlap policy, bounded missed-occurrence catch-up after downtime, and dispatch from a pinned default-branch revision. Manual inputs have validated boolean/enum/bounded-string/list types; pass values as data, not interpolated shell code.
- Explicit extra repository checkouts, destination paths, full-history mode, scoped credentials, and source manifests recording all resolved SHAs. Revalidate grants before fetching; user YAML cannot authorize another repository.
- Native context variables for workspace/temp/run/attempt/source/event/input data, bounded non-secret step/job outputs, explicit per-step shell/env/workdir/conditions, advisory outcomes, and required-versus-optional artifact matching.
- Always-run finalizers have their own bounded cleanup budget on failure/cancel/timeout. Worker-owned cleanup and startup reconciliation run even when repository finalizers cannot; finalizers cannot extend a revoked lease or become an unrestricted next job.
- Jobs run in parallel when dependencies allow; steps share a job's ephemeral workspace/container environment sequentially. `needs` shares no files implicitly.
- Reject cycles, missing dependencies, duplicate IDs, invalid mount/output paths, unsatisfiable resources, and expansion beyond limits.
- Default `/bin/sh` fail-on-command-error semantics documented; Bash requires an image containing Bash. Define workdir, environment precedence, exit/signal, and cleanup behavior.
- Tiny bounded `if` grammar over event metadata/dependency outcomes, with explicit success/failure/always semantics. No arbitrary code evaluation or network access in expressions.
- `hash_files` uses pinned source, sorted paths, bounded counts/bytes, and documented no-match behavior. Server validates structure; worker reports content hashes before cache selection. Define evaluation phase for every expression.
- Resolve image tags to persisted digest/platform per run; production examples prefer digest pins. Reruns retain compiled spec and pinned inputs; new-ref dispatch is distinct.
- YAML references secret names, never values. It cannot grant itself privilege, host mounts, or a stronger trust pool.
- Artifacts specify success/failure/always retention and explicit dependent-job inputs; finalize handoff schema before migrating workflows requiring it.
- Resource defaults/maxima are server policy shown by validation. Every job has finite queue/execution timeouts.
- Release schema, expression reference, and short Rust/Node/Python cookbooks ([recipes](docs/recipes.md)) alongside each version. Schema-assisted generation does not imply automatic Actions compatibility.

## 7. Execution and trust boundaries

- Each worker picks its sandbox from its host ([16.8](#168-microvm-execution-on-kvm-hosts)): rootless Podman without KVM, the only runtime in v0.1, with user namespaces, seccomp, dropped capabilities, no-new-privileges, restricted mounts and cgroup v2; with KVM, after v0.1, a Firecracker (Linux) or Cloud Hypervisor (Windows) microVM per attempt, the default on such hosts. No QEMU.
- No shared host Docker socket or YAML-granted privileged escape hatch. Repositories adapt daemon/cluster tests to ordinary isolated job processes or a separately provisioned, scoped test environment reachable from the job. A job that needs a Docker daemon (Actions `container:`/`services:` in runner mode, Compose lanes) runs in a microVM, never in a container sandbox. Any powerful runtime needs operator-granted capabilities and separate trust boundaries.
- Separate job networks from control endpoints, host services, cloud metadata, and credentials; enforce through runtime/firewall policy. Jobs have no network by default; an operator may grant outbound network per worker (`job_network = "egress"`: rootless pasta with no route to the host, and the worker advertises the label `egress`), for trusted code only ([executor](docs/executor.md#job-network)).
- Checkout exact SHA with short-lived repo-scoped credentials in a worker checkout helper. Never leave tokens in URLs, job environment, Git config, or logs. Submodules/LFS need explicit support and credential scoping.
- Optional worker-local Git mirrors with locked updates, object validation, repository/trust separation, and job workspaces unable to mutate shared objects/configuration.
- PR checkout defaults to head; persist head/base SHA. A future synthetic merge policy records its actual tested SHA. Checks must identify what was tested.
- Destroy workspaces/writable clones after finalization; reconcile crash leftovers. Runtime, network, OOM, timeout, and log failures are distinct from command failures.
- Runner mode ([16.10](#1610-github-actions-runner-mode)) runs the official GitHub Actions runner inside these same sandboxes, one ephemeral just-in-time runner per job, on egress pools (the runner must reach GitHub); its registration config is a single-use credential that never reaches a log, and Actions secrets never reach Sentinel.
- Fork execution off in v0.1, in both modes. Hostile code runs only in the microVM fork pool (after v0.1: separate pool and caches, no secrets, egress off, nested KVM off by default). Rootless containers share the kernel and are not a hostile multi-tenant isolation guarantee.

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
  cache/<scope>/<entry>/        native caches; runner mode's actions/cache entries (after v0.1)
  mirrors/<repository-id>/
  images/<digest>/              microVM root filesystems and snapshots (after v0.1)
```

### Durability, quotas, and recovery

- Immutable checksummed objects and versioned manifests. Authorize logical IDs; never expose arbitrary filesystem paths.
- Stream to temp, verify length/digest, flush file, same-filesystem atomic rename, flush directory, then commit reference. A crash may leave an orphan, never a published incomplete object.
- Idempotent resumable uploads, bounded chunks/concurrency, committed-only reads, orphan cleanup, and integrity reconciliation. Defend traversal/symlink escapes during export/extraction.
- Controller disk is default durable log/artifact destination. Workers retain spools until acknowledged. Local caches are disposable; remote replication optional. In runner mode the same stores receive `actions/cache` and `upload-artifact` traffic, served transparently on the worker host (16.10), so a runner-mode job's caches and artifacts are never stored at GitHub and count against the same tenant quotas.
- Persist log completeness/finalization. Worker-disk loss may lose unacknowledged bytes; report gaps. Document/test the exact durability acknowledgement boundary.
- Quotas per installation/repo/run plus global high/low watermarks and reserved metadata/spool space. Stop admission before disk exhaustion.
- Retention and byte caps are configurable policy with defaults of 14 days for logs and 90 days for artifacts (a pipeline's own `retain` can only shorten it), and byte-capped LRU caches ([retention](docs/retention.md)).
- GC respects active readers/uploads/jobs/cache leases. Manifest deletion and object reclamation are separate stages; never delete mounted data.
- Online SQLite backup plus consistent manifest/object snapshot, migrations, integrity checks, restore drills, and upgrade/rollback guide. Back up secret encryption keys separately and restore matching metadata/objects.

### Local-first cache

1. Immutable worker-local entries with writable per-job clones and atomic success publication.
   Source-derived `hash_files` keys use [bounded Linux descriptor-rooted resolution](docs/hash-files.md) before writable execution, or against an immutable snapshot. No symlink/mount traversal or unsafe non-Linux fallback; filesystem confinement alone does not provide a content snapshot.
2. Reflinks where supported; benchmark btrfs snapshots for large directory trees before declaring that optimized backend supported.
3. Ordinary filesystems use safe bounded copies and report backend/cost. Never writable hardlinks. ZFS/overlay-specific backends wait for evidence/conformance tests.
4. Scope keys by installation/repo ID, trust class, architecture, OS, image/toolchain identity, format version, and user key; runner-mode entries carry the same scope plus the Actions cache key and version. PR writes cannot poison protected-branch caches; downward sharing requires explicit policy and secret-free content.
5. Concurrent writers produce distinct immutable generations; choose winners transactionally. Corrupt/incompatible/missing cache is a miss, not build failure.
6. Scheduler prefers local copies. Cross-worker hydration uses portable manifests and checksummed compressed transfer; local snapshot mounts do not work across hosts by magic.
7. Begin with simple versioned object transfer. Add chunk dedup only if measurements justify it. Filesystem send/receive can be an optional same-backend optimization, not the portable protocol.
8. Report hit/miss/partial, bytes, backend, key dimensions, and miss reason. Compiler-cache persistence is a first-class fast path; optional remote compiler protocols follow measured need. A lockfile alone does not capture all compiler inputs.

### Performance-first cache contract

Cache **toolchains, source objects, dependencies, compiler intermediates, extracted images, and task outputs** separately. Keep stable compiler-cache namespaces across source/lockfile edits where the tool validates entries; exact dependency materializations require complete compatibility keys. Restore prefixes never cross tenant/trust/toolchain boundaries. See [cache design](docs/performance-research.md#sentinel-cache-design).

- Default job-private writable clones, source mirror leases, bounded prefetch, stampede suppression, and measured locality-aware placement. Snapshot mount time and first-touch cost are separate measurements.
- Prefer local materialization over compress/upload/download/extract. Stop a slow optional remote restore when estimated rebuild is cheaper. Required artifacts are never optional cache misses.
- Build-tool caches stay tool-owned; Sentinel need not understand every language's compiler. Expose generic paths, policies, metrics, and versioned evidence reports.
- Reuse test/task outcomes only for explicitly opted-in deterministic declared-input tasks with sufficient isolation; default arbitrary shell/network/secret/time-sensitive tests always execute. Reuse is visible with producing run/input digest, never relabeled fresh execution. A pilot's fresh-execution flags (Go `-count=1` where used) stay until its check contract is explicitly changed.
- Required pass publication waits for required results/artifacts and durable completion, not optional cache replication/GC. Local publication is atomic; background upload has bounded backlog and quota.

### External S3 option

Adapter for immutable artifacts/log segments and optional portable cache exports; SQLite metadata stays local. Configurable endpoint/region/bucket/prefix, TLS, scoped credentials, streaming/multipart, checksums, retries/abort cleanup, range reads, and named compatibility tests.

On S3 outage retain bounded spool and expose degraded durability; enforce admission/finalization policy when full. Cache upload may degrade to a miss; required artifact persistence cannot silently disappear. No MinIO dependency and no goal of implementing an S3 server.

## 9. Logs and agent diagnostics

### Capture once, present two ways

- Bounded stdout/stderr frames: run/job/step/attempt IDs, sequence, timestamp, stream, and byte/line offsets. Preserve per-source order, not fictional exact ordering across streams.
- Redact before storage/index/transport/UI. Handle secrets split across reads, long lines, invalid UTF-8, ANSI, and binary output. Arbitrary transformations of secrets cannot be reliably redacted.
- Segmented append logs with sparse step/time/line indexes; compress sealed segments and stream active ones. No per-line SQLite writes or whole-file reads to obtain tails.
- Bounded memory queues and worker disk spool isolate execution from slow consumers. Resume by cursor. At output caps, keep draining pipes, emit explicit truncation/gap events, and mark completeness; no unbounded RAM or silent loss.
- Initial diagnostic inputs: versioned Sentinel events, Go test JSON (package/test/subtest/panic/race), Rust compiler JSON, JUnit, and a generic report schema. Repositories convert their own evidence to that schema in repository scripts; no repository-specific parser in the core. Bound parser size/time and treat all content as untrusted. Plain commands still expose exit/signal/OOM/timeout and excerpts; distinguish advisory failure, incomplete evidence, skipped scope, reused result, and fresh full pass.

### Failure API contract

`get_failure`: status/failure class, failed command/step, exit/signal, parsed message/file/line/test when available, relevant contextual excerpts, resource/cache/timing clues, and stable evidence references. Select the actual compiler/test error rather than only the final lines; include fallback tail when parsing fails.

Default budget **8 KiB for the whole response / 20 diagnostics**, configurable hard ceiling **64 KiB**. At the default the view is cut to fit as a whole: the fallback tail is trimmed first, then long diagnostic messages are shortened, and diagnostics are dropped last. Responses include schema version, `truncated`, `next_cursor` where applicable, `log_complete`, and omitted counts when known. Bytes are enforceable; token estimates are advisory.

Log queries: step/attempt, cursors, literal search, context, line/byte budget, incremental `since`. Regex later only with bounded non-backtracking execution. Deterministic summaries require no model API or token bill. Optional model summaries ([16.6](#166-ai-assistance)) cite evidence and cannot replace logs or determine outcomes.

MCP labels logs/repository content as untrusted data, never agent instructions. Inferred root causes are labeled as inference. Runner-mode jobs keep their logs on GitHub; Sentinel's diagnostics cover native jobs and runner-mode lifecycle only.

## 10. API, CLI, MCP, and UI

Shared versioned API/authorization, stable IDs, pagination, structured errors, request IDs, mutation idempotency, and resumable event cursors. Publish OpenAPI/schema artifacts. SSE is sufficient for browser updates; workers need bidirectional sessions.

The CLI covers sign-in and profiles (`auth`, `context`), runs (`run`, `status`, `wait`, `job`, `log`), operations (`workers`, `queue`, `cache`, `artifact`, `secret`, `doctor`), offline `pipeline validate|explain`, and the host-local `admin` commands; the implemented command surface is in [CLI](docs/cli.md).

CLI: human default, JSON/NDJSON, documented exit codes distinguishing failed run/pending/transport error. Bounded event-driven `wait` avoids agent polling loops. `doctor` diagnoses runtime/filesystem/cgroups/connectivity/disk/GitHub without credentials. Linux and Windows CLI; execution is Linux-only; macOS is not supported.

MCP exposes read tools for runs, failures, logs, queue explanations and pipelines, and mutations (dispatch, rerun, cancel) with scopes, idempotency, audit, and accurate tool annotations; the tool list is in [MCP](docs/mcp.md). Secret creation/update is available to authorized agents through CLI secure input, with metadata-only MCP inspection; no need to put secret values into model tool arguments. See [OAuth and secrets contract](docs/auth-and-secrets.md).

Stdio uses the CLI's locally provisioned credential source; it does not run an HTTP OAuth handshake over stdio. Streamable HTTP implements MCP OAuth discovery, authorization code + PKCE, resource/audience validation, and supported client registration. CLI uses browser OAuth + PKCE or device authorization for headless hosts. Sentinel issues scoped tokens after GitHub/local sign-in; GitHub tokens are not Sentinel API tokens. Both transports share the API authorization layer.

### Human UI

`sentinel-web` runs beside the controller, renders pages as the signed-in person, streams live run and log updates as server-sent events (the controller's long polls, held on the browser's behalf) and proxies the controller's routes as one origin. The current code is Nuxt 4 (Vue, TypeScript, Nuxt UI), chosen after measuring the accessible live-log view four ways: windowing is what matters ([web interface](docs/web-ui.md#stack-choice)). It is being replaced, view by view, by a TanStack Start application with the same process role and budgets against a measured baseline ([16.4](#164-web-interface-on-tanstack-start)).

- Runs by installation/repo/branch/PR/SHA, queue/execute timings, cache effectiveness.
- Failure summary first, file/test evidence links, job DAG, step timelines.
- Virtualized logs, folded successes, contextual search, stable links, reconnect cursors, visible gaps/truncation.
- Worker capacities/reservations, labels, drain/offline, disk backend/pressure, direct/relayed path.
- Queue explanations, cache miss reasons, artifacts, cancel/rerun, GitHub sync lag.
- Keyboard accessibility, contrast/status labels, responsive layout, bounded DOM/memory.
- Built-in counters/histograms and scrapeable metrics; external observability optional.
- Tenant/repository switcher with explicit active scope. Super-admin console for registration requests, users/tenants, suspension, pool grants, quotas, and audit; tenant admins get only their own administration views.

## 11. Git sources, GitHub and authorization

### Authentication, registration, and multiple organizations

**Model:** one deployment -> many tenants/namespaces -> authorized Git repository connections, optionally associated with a forge installation. Users may belong to several tenants with different roles. Personal namespaces use the same model. A tenant can link several GitHub organizations; an installation has one owning tenant by default, preventing accidental duplicate intake or conflicting required checks. Generic repositories have Sentinel-owned stable IDs and need no installation. Cross-tenant sharing is never inferred from matching URLs, names, email domains, or org membership.

**Authentication:** GitHub sign-in or local Sentinel accounts, with local administrative recovery so operators are not locked out during GitHub outages. Generic Git users need no GitHub identity; human sign-in is independent of repository access credentials. Local passwords use a maintained Argon2id implementation with rate limits, breached-attempt throttling, secure recovery, and no default password. Support TOTP plus hashed one-use recovery codes for local privileged accounts; require step-up for super-admin role/registration/auth-policy changes. External OIDC/SSO can follow through an auth-provider boundary; no mandatory identity server.

- Bootstrap the first super admin with a local operator command or expiring single-use setup secret, not “first visitor wins.” Disable bootstrap after successful setup; provide audited host-local recovery and prevent removing the last active super admin.
- GitHub identity is provider + immutable user ID. Do not auto-link accounts by email. Account linking requires authentication of both identities. Sign-in uses validated state/redirects and PKCE where supported; the flow is in [GitHub sign-in](docs/github-sign-in.md).
- Opaque server-side sessions, Secure/HttpOnly/SameSite cookies, rotation on login/role change, idle/absolute expiry, logout-all, CSRF protection, and immediate account suspension checks.
- CLI/browser login issues scoped, expiring tokens using a browser handoff bound to the initiating client. MCP and service accounts cannot inherit ambient super-admin authority. Hash opaque token secrets at rest; allow listing metadata, revocation, and last-used audit.
- Implement the complete [OAuth and secret management contract](docs/auth-and-secrets.md): public CLI client/PKCE, device grant, refresh rotation/revocation, MCP metadata/audience/client compatibility, OS credential storage, scoped CLI secret writes/rotation, and job-time injection. Interactive login is reusable for humans/agents; noninteractive agents use explicit bounded service grants.

**Registration policy:** default `invite_only`; super admin may choose `closed` or `approval_required` per deployment. A successful GitHub login is authentication, not automatic admission. Pending accounts have no tenant data or worker access. Approvals/rejections, invitations, expiry, revocation, and suspensions are visible in the admin console/API and audited.

Account registration, tenant creation, GitHub App installation binding, and runner enrollment are separate decisions. Allow existing members to sign in when registration is closed. Invitations bind to a verified identity (or authenticated acceptance with explicit admin approval), tenant, maximum role, expiry, and one-time nonce. Installing the App on GitHub alone cannot create an approved Sentinel tenant or allocate compute. Unknown installations remain unbound/inactive until an authorized binding exists. No mandatory email delivery (optional Resend): an admin can deliver a one-time invitation link out of band.

| Role | Scope and powers |
|---|---|
| Super admin | Deployment auth/registration policy, approve/create/suspend tenants, manage platform operators/pool grants/global quotas, audit and recovery |
| Tenant owner/admin | Own memberships/invites, approved installation bindings, repo configuration/secrets, tenant pools and budgets within platform limits |
| Repository operator | Dispatch/rerun/cancel and read results for granted repos; no membership or platform changes |
| Repository reader | Read permitted runs/logs/artifacts and bounded diagnostics |
| Service account | Explicit tenant/repo/action scopes and expiry; no interactive registration privileges |

Super-admin control is an explicit platform privilege, not an org role. Do not expose stored secret values in any admin UI. Platform operators with host/database access remain trusted; tenant isolation is not a claim to hide data from the deployment owner. Audit elevated cross-tenant administrative access.

The [authorization contract](docs/authorization.md) keeps platform administration separate from repository data access: super admins need ordinary membership/grants for repository queries. Human tenant admins have own-tenant repository authority capped by credential scopes; readers/operators/service accounts need explicit repo grants. Service accounts are permanently tenant-bound and cannot administer identities. Membership is a live ceiling on grants; secret-write is independent of run permission. Client operations derive ownership through repository rows, not a selected tenant context.

**Tenant boundaries:** require tenant scope for every lookup, search, event subscription, object download, cursor, mutation, secret, cache, checkout, and worker grant. UI context/CLI defaults are convenience only; server derives authorization from authenticated membership and resource ownership. No cross-tenant dedup visibility, signed-link reuse, queue-detail leakage, or guessed-ID access. Use tenant-partitioned object namespaces; short-lived download links bind tenant and object. Running session/event streams are reauthorized on membership changes.

Tenant suspension stops intake/schedules/dispatch, revokes sessions/tokens/grants, requests running-job cancellation, and preserves retained evidence under policy. GitHub installation removal immediately prevents new source-token issuance and triggers reconciliation. Worker pools are tenant-dedicated by default; platform-managed shared pools have explicit tenant grants and isolation requirements. Approval of an unrelated org does not make its code trusted on another org's machines.

Acceptance tests: at least two orgs and a personal namespace on one deployment; overlapping user memberships with different roles; invitation races/reuse; last-admin protection/recovery; pending/closed registration; unbound installation; suspension during streaming/execution; tenant ID/cursor/artifact/cache substitution; queue fairness under one noisy tenant; cross-repo checkout denial; role revocation across UI/CLI/MCP.

### Git sources and forge boundaries

Three concerns stay separate: trigger adapters -> shared authorized source/pipeline resolution and durable run creation -> existing execution plus optional forge result publishing. GitHub's native PR feedback is required; generic Git runs publish results through Sentinel UI/API. Dedicated Gitea, Forgejo and GitLab adapters are deferred, not prerequisites for their repositories to run.

- **Repository binding:** a tenant-owned stable repository ID binds an administrator-approved clone URL, allowed refs, pipeline path and credential reference. Support self-hosted hostnames/ports, private CA trust and pinned SSH host trust. Restrict transports and destinations through deployment policy; event bodies and pipeline YAML cannot replace the bound remote or grant source access. Generic repositories are never encoded as fake GitHub installations.
- **Source credentials:** public repositories, read-only HTTPS credentials and SSH deploy keys share a scoped source-access path with GitHub App tokens. Generic credentials may be long-lived; seal stored secrets with the existing key-outside-database mechanism, support rotation/revocation and revalidate live grants before issuing fetch access. Deliver credentials only to authorized source-resolution/checkout operations, outside immutable specs, URLs, logs and job environments, over the authenticated worker link under versioned protocol rules. Stored secrets use [sealed storage](docs/sealed-storage.md); scoped secret management is in [secrets](docs/secrets.md).
- **Events:** manual API calls, authenticated generic ref-update events, GitHub webhooks and poll observations feed one bounded durable intake. The generic contract identifies the bound repository, stable delivery ID, ref and old/new object IDs; authenticate before accepting, scope deduplication to the connection/repository and persist before acknowledgement. A documented server-side `post-receive` hook/relay uses bounded durable retry and exposes delivery/overflow failures; it never waits for CI completion. Hook availability depends on host administration; native forge webhook payloads need translation and are not automatically compatible.
- **Resolution:** resolve the policy-selected pipeline revision and checkout revision through Git, pin both before compilation/admission, and fail explicitly when a revision is no longer fetchable. Preserve explicit manual pipeline submission as a distinct provenance mode. Bound subprocess time, output, fetched data and concurrent work; remote I/O never holds the database writer. Define branch/tag create/delete, annotated-tag peeling, force-push, duplicate/reordered events and overlap between intake methods. A commit ID alone is not a delivery identity: returning a ref to an earlier commit is a distinct transition. PR head/base/tested-merge provenance and trust policies belong to the GitHub adapter; Git refs alone do not prove PR metadata or trusted fork code.
- **Polling:** opt-in `git ls-remote` for selected refs, with per-host/concurrency/output/time budgets, jitter and backoff. Persist observations and resulting intake atomically, or through recoverable pending observations, so a crash cannot advance a cursor while losing work. Specify initial discovery and deletion behavior. Polling builds observed ref changes and can miss intermediate pushes; it is not an every-push delivery guarantee or the scheduler's dispatch clock. Prefer events for low latency and measure polling overhead independently.
- **Feedback:** GitHub App authentication, webhook/PR semantics and Checks publishing remain adapter-specific. Reuse durable outbox delivery mechanics, but do not make a forge publisher mandatory for generic runs or block dispatch on external status updates. Git alone provides neither PR/MR lifecycle nor native merge-protection checks. Generic Git operation therefore has no native PR/MR feedback guarantee for other forges.
- **Acceptance:** retain the real GitHub PR/required-check pilot and add self-hosted Gitea, Forgejo, GitLab and bare-repository fixtures exercised without provider APIs. Cover private HTTPS/SSH, manual/hook/poll intake, pinned pipeline/source, truthful outcomes, revocation, duplicate delivery, restart and tenant isolation. Report unavailable fixtures as blockers and distinguish trigger detection, source resolution, dispatch and external feedback latency.

### GitHub integration

Native GitHub PR feedback is a required M1 capability, alongside generic Git support. The adapter uses the shared source/intake/run path above.

- One GitHub App. Org/personal installations with selected repos. Store immutable IDs; handle install removal/suspension, repo access change/rename/transfer.
- Base permissions: contents read, checks write, pull requests read, metadata read. Org members read only for org-membership policies; personal installations use owner/collaborator or explicit grants. A feature asks the same App for more only when a tenant turns it on, and refuses setup naming what is missing: runner mode adds Actions read and organization self-hosted runners write (repository administration write for a personal namespace) for `workflow_job` intake and just-in-time runners ([16.10](#1610-github-actions-runner-mode)); guided migration adds contents, pull requests and workflows write ([16.5](#165-guided-github-actions-migration)). Runner-mode jobs publish no Sentinel checks: GitHub reports them under the workflow's own job names.
- Separate human login and installation credentials. Repository reader/operator/admin roles, periodic revalidation/revocation; org membership need not grant all mutations.
- Short-lived scoped checkout tokens; no classic PAT in the normal path. Hashed CLI tokens, expiring sessions, encrypted secret values with key outside SQLite, rotation, CSRF protection, and audit.
- Durable dedup/outbox retries, rate-limit/backoff, missed-delivery and pending-check reconciliation after outages. Accepted work dispatch is independent of Checks latency.
- Subscribe to push, relevant PR actions, check rerequests, installation/repo-access events, and `workflow_job` when runner mode is on. Explicit draft/filter policy; duplicates/reordering handled.
- Per-job checks `sentinel / <job>` plus stable aggregate required check `sentinel / ci`. Invalid config/required failures fail aggregate. Define skipped-job/filter semantics so required checks do not remain pending forever.
- With named pipelines use namespaced job checks and stable aggregates such as `sentinel / ci` and `sentinel / acceptance`. A manual focused diagnostic run never satisfies the full acceptance aggregate; scheduled/manual/release results retain distinct scope and identity.
- Map outcomes to GitHub conclusions with `details_url`; persist external check IDs/attempts. Reconcile ambiguous API timeouts before creating duplicates. Verify `gh pr checks` and rerequests end-to-end.
- Correct commit/PR association; test stale completions, new pushes, deleted refs, reruns, and checkout policy. `merge_group` support is mandatory before migrating repos using merge queues.
- GitHub outages can block intake/source fetch; explain that separately from worker capacity. Jobs on Sentinel, native or runner mode, consume no GitHub-hosted runner minutes and store no artifacts or caches at GitHub, but GitHub API limits and unrelated workflows still exist.

## 12. Performance targets and evidence

Primary relative product target (B11): **Sentinel trigger-to-required-check p95 at most 0.50 × Blacksmith's p95 for the same checks and conditions**. The independent absolute target (B08) remains **warm, representative PR required-check completion p95 < 60 seconds on the same hardware that previously took >=300 seconds**. Specify exact checks, inputs, resources, freshness and warm state before measuring. Measure first useful failure, required-check completion and full audit/acceptance completion separately; a fast partial result does not mean all checks passed. [Performance research](docs/performance-research.md) defines the optimization sequence and feasibility gates; pilot measurements use contract `pilots-ci` revision 4 and B11 uses its own frozen contract.

These are targets, **not measured results**. Revision 4 pins `kvm-host` and separate CCDs for Sentinel and the GitHub baseline. Its current records have no qualifying >=300 s B08 baseline (maxima 109 s cli, 88 s gson, 30 s ripgrep) and ten-sample warm nearest-rank p95 values of 64.08 s, 44.02 s and 21.39 s. They are development evidence, not a release-grade tail or a Blacksmith comparison. No Blacksmith baseline exists, so B11 is blocked by access. Publish exact hardware/kernel/filesystem/runtime/revision; records from another host or contract are separate series. Historical latency budgets met on 2026-10-22 are revalidated on the current runtime before closure. The same budgets apply to microVM sandboxes on the snapshot-restore path and to runner mode from event receipt to runner online.

| Metric | Initial target |
|---|---|
| Durable webhook ACK, excluding GitHub delivery | p95 < 250 ms |
| Push event -> job ready (pipeline resolved and run created), probe fixture | p95 < 250 ms |
| Dependency-ready + available capacity -> worker offer | p95 < 100 ms; p99 < 250 ms |
| Offer -> ack, connected LAN worker | p95 < 100 ms |
| Ready -> first user process, warm reference fixture | p95 < 2 s; p99 < 5 s |
| Push event -> first user process, warm probe fixture | p95 < 1 s |
| Local optimized cache preparation, published fixed fixture | p95 < 500 ms; report bytes/file count/backend |
| Log capture -> UI/CLI on LAN | p95 < 250 ms |
| Cancel -> termination, healthy connection | p95 < 2 s excluding configured grace |
| Indexed failure query on 100 MiB run | p95 < 200 ms; <= 8 KiB response as a whole |
| Idle server / worker RSS excluding runtime/jobs | provisional < 150 / 75 MiB |
| Combined idle control CPU | provisional < 1% of one core |

Measure delivery, intake/config, dependency wait, capacity wait, dispatch, checkout, image pull, cache restore, container setup, each step, cache commit, artifact upload, log flush, and Checks propagation. Include total push-to-feedback; fast dispatch alone is insufficient.

Benchmark matrix:

- No-op; the pilots' lanes as their live fork pipelines, online — cli `go.yml` `build` (ubuntu row: race tests, builds), ripgrep's stable `test` row, gson `build` on JDK 17/21/25 — cold (including downloads), warm and small-edit; Node install/tests; many tiny files, large artifacts, noisy 100 MiB logs, 10 GiB caches with published file distributions. Follow the [pilot benchmark and cutover gates](docs/pilot-repositories.md#performance-and-cutover-gates).
- Fully cold, image/source/dependency/compiler warm, exact hit/miss/invalidation/corruption; report bytes and latency.
- Same-host direct runtime, healthy GitHub self-hosted runner, Woodpecker, Sentinel. Equal resources, commands, image/source, isolation, warm state. Runner mode against GitHub-hosted runners and the Blacksmith probe's queue → job reference ([16.10](#1610-github-actions-runner-mode)); microVMs against rootless Podman on the same KVM host.
- Actual Blacksmith executions for B11 once access exists; disclose hosted hardware/network differences and never call them same-hardware evidence. Vendor multipliers and the one-run startup probe are not Sentinel evidence.
- Fleet 1/3/10, bursts 1/10/100; correctness/load target 100 workers and 10,000 queued jobs. Report p50/p95/p99/max wait/throughput/CPU/RSS/I/O/failure rate. Saturated queue wait is not subject to idle-capacity SLO.
- LAN, Tailcat direct/relay, injected latency/loss, slow/full disk, controller/worker restart, stale lease, missed webhook, S3 outage.
- Repeated trials with sample counts/variance and raw results. Fixed-hardware regression gate initially 10% p95 overhead regression, accounting for noise.

### B11 acceptance contract

For each selected lane and condition, `Sentinel trigger-to-required-check p95 / Blacksmith trigger-to-required-check p95 <= 0.50`. Use identical source SHA, commands, assertions, freshness policy, required jobs/artifacts and resource envelope. Keep cold, warm and small-edit series independent. Interleave 100 paired release samples per lane/condition, publish raw samples and variance, and require a one-sided 95% bootstrap upper confidence bound on the paired log-duration ratio below 0.50. Any incorrect or failed required check fails the gate; failures never disappear from the evidence to improve timings. Report job-start-to-finish and every phase beside the end-to-end clock so queue time cannot be hidden. If Blacksmith cannot provide equivalent resources, label the result a hosted-service comparison. B11 remains blocked until actual Blacksmith runs exist and cannot be closed by documentation, GitHub self-hosted records or startup observations.

Profile before custom allocators, mmap everywhere, io_uring, bespoke indexes, dedup, or warm microVM pools. Optimize measured bottlenecks. Warm pools never retain writable job state or secrets between jobs.

## 13. Milestones and release gates

### M0 — Preserve legacy and validate design

Complete: the original `main` is preserved as `legacy`, and baselines and spikes (Tailcat direct/relay, rootless cgroups, SQLite dispatch, cache cloning) are recorded in [`bench/`](bench/) and [feasibility probes](docs/feasibility-probes.md). The remaining inputs are the open questions in section 14.

### M1 — Durable single-host vertical slice

- Rust server/worker, SQLite migrations, authenticated enrollment/session, strict basic schema, generic Git bindings and manual/hook/opt-in polling intake, one GitHub App repo, exact checkout, isolated container, spool, GitHub Checks outbox.
- Leases/reservations/timeouts/cancel/dedup/restart reconciliation from the start; CLI status/logs and minimal new run UI.
- First-admin bootstrap, local/GitHub login, sessions, tenant-scoped data model, reader/operator/admin authorization, and closed/invite-only registration before real private repository access.

Gate: real GitHub PR green/red with native required Checks; generic Git pilots on self-hosted Gitea/Forgejo/GitLab and a bare repository produce truthful Sentinel UI/API results without provider APIs; duplicate delivery creates no duplicate logical run; restart/cancel tests pass; server never executes jobs. Other forge-native PR/MR feedback is deferred. No cache required yet.

### M2 — Fleet and queue reliability

- DAG, fairness/aging, per-repo concurrency, superseded cancel, labels/resources, drain/revoke, queue explanations, org/personal installations.
- Direct/Tailcat sessions, owned relay documentation, fenced reconnect, bounded control/bulk paths.
- Q11 UI-generated worker-only Tailcat enrollment and Q12 controller-owned host ceilings, priority and expected-finish placement. Additional machines are workers, never secondary controllers.
- Super-admin registration console, org/personal tenant bindings, suspension/revocation, pool grants/fairness and cross-tenant tests. Profile real CI workloads across toolchains (the pilot repositories). Select incremental pipeline features by measured CI value; Docker/VM compatibility is not a gate.

Gate: Q13 proves real enrollment, revocation, host-cap changes and placement across the verification hosts. Three workers load-balance bursts within allocations; duplicate identities cannot multiply host ceilings; eligible idle capacity is used promptly; priority cannot bypass hard admission; stale completions cannot replace current state; relay/partition/restart tests pass.

### M3 — Locality and storage

- Immutable caches/safe copy/optimized backend; artifacts and DAG handoff; segmented indexes; quotas/retention/GC/restore.
- Portable remote hydration and optional S3 tested for interruption/corruption.
- Toolchain cache recipes for Go/Rust/Node/Python/Java and a custom-tool fixture; specialized image/source/compiler locality, invalidation, concurrent publication, remote-restore cost bounds, and required-result versus optional-cache finalization. No repository-specific executor.

Gate: measured warm improvement; no concurrent cache corruption or lower-trust poisoning; disk-pressure/restore drills pass; log/artifact completeness is truthful.

### M4 — Agent and human experience

- Bounded Go/Rust/JUnit/generic report evidence, cursor search, JSON/wait CLI, OAuth CLI/MCP, authorized CLI secret management, and docs. Verify browser/device/refresh/revoke flows and secret handling without plaintext echo.
- Accessible virtualized UI, worker/queue/cache pages, GitHub rerequest/stable required-check semantics.

Gate: agent locates actual error in noisy 100 MiB fixture using bounded responses, retrieves evidence, and reruns without full dumps; human can find same error/queue reason; authorization/parser-limit tests pass.

### M5 — Pilot, benchmark, replace

- Shadow the pilots while their Actions CI remains authoritative; compare results, filters, secrets, artifacts, merge behavior, latency.
- Adapt the [pilot repositories'](docs/pilot-repositories.md) lanes to Sentinel's execution/cache/report contracts and update their tests/docs on the forks. Other lanes migrate independently or stay external; full workflow parity is not a Sentinel release gate. Benchmark multiple toolchains and publish progress against B08's sub-minute target and B11's Blacksmith-relative target, including unmet bottlenecks.
- Publish evidence/limitations; meet reference targets and scale/fault tests. B08 remains an absolute objective; B11 must demonstrate the 2× Blacksmith end-to-end gate or remain an explicit blocker.
- Change required checks repo by repo after parity; disable superseded Actions to stop duplicate execution. Preserve explicit rollback to old workflows/required checks. In v0.1 the pilots switch natively; switching by `runs-on:` alone is the runner-mode path of M6.
- Re-audit Parts 01–14 against the current rules and rework what it finds (`TODO.md` Part 24, [16.9](#169-re-audit-and-rework-of-earlier-parts)). This starts before the remaining performance work and closes only after Q13, B09 and B11.
- Tag v0.1 with Linux packages/systemd/container examples, upgrade/backup/recovery docs, dependency/license inventory, and Q11's audited worker onboarding.

Gate: migrated repos run entirely under Sentinel; org/personal installs and remote workers work; storage is ours; no hosted Sentinel account needed; claims match benchmarks; Parts 01–14 re-audited; Q13, B09 and B11 pass.

### M6 — Breadth after v0.1

- In order: GitHub Actions runner mode on rootless Podman (Part 25), Windows jobs (Part 17: guests on KVM hosts first, the native executor when a Windows host is designated), first-class artifacts and default tenant storage limits serving both modes (Parts 18–19), the TanStack Start interface (Part 20), guided migration by label swap (Part 21) and opt-in AI assistance (Part 22) ([section 16](#16-planned-scope-after-v01)). Part 23's Linux host detection/runtime routing/Firecracker implementation landed early and its M01–M06/M08 verification is pulled into the current release; Windows guests remain here unless separately promoted.

Gate: each part's own measured gates in section 16; no regression of the B03 budgets or the B09 regression gate; a pilot migrates by changing `runs-on:` alone; the pilots' Windows lanes run on Sentinel; microVM overhead against rootless Podman published per lane; AI disabled or failing changes no run outcome or timing.

## 14. Decisions and open questions

Adopted: purpose-built performance-first Rust CI engine; strict native pipelines plus a GitHub Actions runner mode for migration by `runs-on:` (one GitHub App, permissions per enabled feature); preserved legacy/new UI (Nuxt now, TanStack Start next); multi-org auth/super-admin registrations; OAuth CLI/MCP and scoped secret management; one active controller with UI-generated worker-only Tailcat enrollment, controller-owned host ceilings/priority and fastest-eligible placement; Linux-first fleet with the sandbox chosen by host (rootless Podman; Firecracker/Cloud Hypervisor microVMs with KVM; no QEMU) and operator-granted egress; durable push scheduling with pushed cancellation; first-class local/compiler/image caches and artifacts on Sentinel's own disks for both modes; SQLite/owned file storage; optional S3; pinned Tailcat/direct TLS; shared API; bounded diagnostics (an 8 KiB default failure view); advisory AI on Effect 4 and OpenRouter, off by default; B11's 2× Blacksmith objective plus B08's same-hardware sub-minute ambition measured on the pilots; Part 24 starting before further optimization and closing before release; MIT/no usage gate. Supporting many project tools does not mean a generic automation framework. Repository adaptation must not dictate fundamental runtime changes.

Open questions, to resolve through hardware and workflow evidence:

1. Relay host and RTT for remote workers (the three verification hosts are recorded in [development](docs/development.md#where-tests-run)).
2. Repositories blocked by services, matrices, image publishing, deployments, merge queues and forks.
3. The optimized cache backend (btrfs/ZFS snapshots against reflinks and safe copies).
4. Tailcat pin and upgrade policy, wire framing and bulk concurrency.
5. The Windows isolation runtime (job object with slot accounts, AppContainer, or Windows containers), from the N02 measurements ([16.1](#161-windows-workers)).
6. The default tenant storage limit's value and the AI data-policy default for hosted deployments ([16.3](#163-default-tenant-storage-limits), [16.6](#166-ai-assistance)).
7. Whether Windows guests on KVM hosts come before the native Windows executor (`TODO.md` N00 assumes so; the owner confirms), and whether one VMM (Cloud Hypervisor) serves Linux guests too, only if M02 measures it matching Firecracker within noise ([16.8](#168-microvm-execution-on-kvm-hosts)).

Decided with evidence: retention and byte defaults ([retention](docs/retention.md)); windowing as what makes the live-log view fast ([web interface](docs/web-ui.md#stack-choice)); backup recovery goals of RPO <= 1 hour and RTO <= 15 minutes for up to 100 GiB ([backup](docs/backup.md)); the S3-outage policy of a bounded backlog on the controller's disk, then closed admission for new artifacts and uploads ([s3](docs/s3.md#degraded-durability-and-admission)).

These gates do not defer scheduling correctness or multi-host design until after v1.

## 15. Sources and verification notes

Inspected 2026-09-13; pin versions and recheck exact behavior during implementation.

- [Pilot workloads](docs/pilot-repositories.md): the three upstream projects' workflow files read through the GitHub API on 2026-10-22.
- [Blacksmith](https://www.blacksmith.sh/): vendor emphasizes fast hardware, colocated caches, persistent NVMe layers, microVM startup, and observability. Vendor claims are not independent benchmarks.
- [Detailed performance research](docs/performance-research.md): Blacksmith technical docs/blogs, Depot architecture/cache/boot engineering, Bazel/Go cache semantics. [Auth research](docs/auth-and-secrets.md): native-app OAuth, device grant, and versioned MCP authorization specification.
- [Tailcat README/source](https://github.com/tailscale/tailcat): Go CLI/library, account-free NAT transport, owned DERP, keys/forwarding, explicit instability; read through GitHub API. See [feasibility probes](docs/feasibility-probes.md#4-tailcat-unattended-connectivity).
- Verification references to recheck when behavior matters: [Checks](https://docs.github.com/en/rest/checks/runs), [webhooks](https://docs.github.com/en/webhooks/webhook-events-and-payloads), [SQLite WAL](https://www.sqlite.org/wal.html), [backup](https://www.sqlite.org/backup.html), [Woodpecker](https://woodpecker-ci.org/docs/intro), [MCP specification](https://modelcontextprotocol.io/specification/latest). This plan is not an implementation conformance report.
- Sources for section 16 are listed in [16.7](#167-sources-for-section-16).

## 16. Planned scope after v0.1

Design for `TODO.md` Parts 17–23 and 25 (milestone M6, order in [M6](#m6--breadth-after-v01)) and for the Part 24 re-audit (M5, before V05/V06 release qualification). Runner mode comes first because migration must be a label change; microVMs come before Windows workers because Windows jobs on a KVM host run in Windows guests, the KVM host exists (`kvm-host`) and no Windows machine is designated. The exception is the already-landed Linux Part 23 work: M01–M06 and M08 are current-release verification gates, while M07/Windows remains M6 unless promoted. No M6 scope relaxes a boundary above: separate server/worker processes, tenant ownership, durable transitions, bounded resources, no secret values in prompts, URLs or logs. Every gate below is a target to measure, not a result.

### 16.1 Windows workers

**Goal.** Run trusted repository code on Windows hosts as ordinary Sentinel workers, for the pilots' Windows lanes (cli `go.yml` `build` windows-latest row, ripgrep's Windows MSVC/GNU builds) and Windows-only projects. Same controller, same protocol, same scheduler; only the executor differs.

**Host.** A Windows job needs a Windows kernel: rootless Podman on a Linux worker cannot run one, and neither can `reference-host` or `arm64-host`, which have no hardware virtualization ([16.8](#168-microvm-execution-on-kvm-hosts)). Two host models remain: a **Windows guest per job on a KVM-capable Linux host** through the microVM runtime of 16.8 (Cloud Hypervisor with UEFI firmware, restored from a snapshot), the default for Windows jobs on a KVM host by the runtime decision; or a **native Windows worker** (a Windows machine running `sentinel.exe worker`, the design below). The KVM host exists (`kvm-host`) and no Windows machine is designated, so the guest model comes first in `TODO.md` (M07) and the native worker follows when a Windows host is named (N00 records the order; the owner confirms it). Both share the schema, placement and checkout rules below (N03, N06).

**Isolation decision.** Three candidates, decided by measurement (N02) on the pilots' Windows lanes, not by preference:

| Candidate | What isolates | Known cost |
|---|---|---|
| Native process under a job object and a per-slot low-privilege account with a restricted token | job object limits (CPU rate, committed memory, active process count, kill-on-close, UI restrictions); the slot account's ACLs on its workspace and cache; a restricted token with administrators deny-only and privileges removed; Windows Filtering Platform egress rules keyed on the slot account's SID | shares the kernel and the machine's installed toolchains; trusted code only, like rootless Podman on Linux |
| The same plus AppContainer | per-package filesystem, registry and network capability isolation | many build tools (MSBuild, rustup, Go module cache, Maven) assume a user profile and network; compatibility unmeasured |
| Windows containers (process or Hyper-V isolation) | container image per job; Hyper-V isolation gives a separate kernel | process isolation needs a host/container OS build match; Hyper-V adds VM start per job; multi-GiB base images |

Default proposal: the native job-object executor with per-slot accounts is the first supported runtime (trusted code, as on Linux); AppContainer is adopted only if all three pilots' Windows lanes pass under it within the start budget below; Windows containers with Hyper-V isolation are an optional runtime under the same rules as I08 (justified across workloads, benchmarked). Hostile code (I09) is not a goal of any of them.

**Execution.**

- **Slots.** A worker owns N slot accounts (`sentinel-slot-1..N`), created once by the installer (the only administrative step) and never by a job. An attempt runs as one free slot's account with a restricted token; a slot is reused only after its processes are gone, its workspace deleted and its profile's temporary directories emptied.
- **Fresh workspaces.** `<data_dir>\workspaces\<attempt>`, ACL'd to the slot account and the worker service only, created per attempt and removed at finalization; startup reconciliation removes leftovers exactly as on Linux ([reconciliation](docs/reconciliation.md)).
- **Process tree.** Every process starts suspended inside the attempt's job object (`CREATE_SUSPENDED`, assign, resume), so no child escapes before assignment. Cancellation sends `CTRL_BREAK_EVENT` to the step's process group (`CREATE_NEW_PROCESS_GROUP`), waits the configured grace, then `TerminateJobObject`; `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` covers a worker crash. Exit, timeout and job-object memory-limit outcomes map onto the existing failure classes ([executor](docs/executor.md#steps)).
- **Shells.** `shell: pwsh` (default on Windows: `-NoProfile -NonInteractive`, `$ErrorActionPreference = 'Stop'`, a failed native command fails the step), `cmd`, and `bash` when the worker reports Git Bash. Console output code page forced to UTF-8; bytes are captured as on Linux.
- **Logs and redaction.** The same frame, spool, sequence and redaction code (`sentinel-worker` is portable Rust apart from the executor); CRLF is preserved as bytes. Redaction parity is a test gate: the Linux redaction suite runs unchanged against the Windows capture path.
- **Git checkout.** `sentinel-git` with Git for Windows; `core.autocrlf=false`, `core.longpaths=true` and `core.symlinks=false` forced on the checkout so the tested bytes are the commit's (the K04 `autocrlf` breakage is the known failure); credentials stay in the one helper discipline, never in the URL or the job environment.
- **Cache.** `Os::Windows` joins the cache scope, so Linux and Windows entries never mix. On ReFS (including Dev Drive) writable clones use block cloning (`FSCTL_DUPLICATE_EXTENTS_TO_FILE`), the reflink equivalent; on NTFS the safe bounded copy, reported as such. Sentinel never changes Defender, Dev Drive trust or other machine settings itself: the operator guide documents a Dev Drive for `<data_dir>` and its antivirus mode, and `doctor` reports what it finds.
- **Toolchains.** Native jobs have no image: the job declares `runs_on: {os: windows, …}` and the toolchain versions it requires; the worker reports installed toolchains as capability labels and records the resolved versions in the attempt's provenance. A version mismatch is a placement refusal with the missing capability named, never a silent substitute.
- **Worker link.** The same pinned mutual-TLS protocol ([worker link](docs/worker-link.md)); `Hello`/`Profile` gain `os` and the Windows build number under [compatibility](docs/compatibility.md). Identity and enrollment files live under `%ProgramData%\Sentinel\worker`, ACL'd to the service account. Direct TLS first; Tailcat only after its Windows helper passes the Q07 tests.
- **Labels.** Detected and reported: `os=windows`, `windows.build`, `arch`, `fs=refs|ntfs`, `devdrive`, `shell.pwsh`, `shell.bash`, toolchains (`go`, `rust`, `msvc`, `jdk`) with versions; operator labels beside them. The pipeline schema gains `runs_on.os` (default `linux`).
- **Packaging.** `sentinel.exe worker` built with the `worker` feature for `x86_64-pc-windows-msvc` (then `aarch64`); a Windows service through the Service Control Manager under a virtual account (`NT SERVICE\sentinel-worker`); `sentinel worker install-service` creates the slot accounts and the service and is the only command that needs elevation; an MSI or signed zip in V01's release set.

**Verification and gates.** For the native worker, a designated Windows verification host (Windows 11 or Server 2025, Dev Drive on NVMe) is a prerequisite: the test rule ([development](docs/development.md#where-tests-run)) needs a named Windows host before any native Windows worker test runs; Windows guests are verified on `kvm-host`. Gates, on that host: ready → first user process p95 < 2 s and cancel → whole tree gone p95 < 2 s (the Linux budgets); a no-op job-object start reported with its distribution against a bare `CreateProcess`; block-clone versus copy for the B05 fixtures on ReFS and NTFS; cli's Windows build/test row and ripgrep's MSVC build/test under Sentinel against a self-hosted GitHub runner on the same host and caps (B02's method); no leftover process, account session, file or firewall rule after cancel, crash and worker restart; redaction suite parity.

### 16.2 Artifact storage

**What exists.** Declared artifacts are captured at finalization (D03) into tenant-scoped, BLAKE3-addressed objects deduplicated within the tenant, listed by versioned manifests (D01), uploadable in resumable 8 MiB chunks (D02), retained by the pipeline's `retain` shortened to the effective retention (R01), counted against run, repository and tenant quotas, optionally copied to S3 (R02/R03), listed and downloaded per entry through API, CLI and UI ([storage](docs/storage.md#artifact-records-d03), [retention](docs/retention.md), [s3](docs/s3.md)).

**What is added.**

- **Digest-first transfer.** Before sending a file the worker offers `(digest, length)` lists; the controller answers which the tenant already holds, and only missing bodies travel. The answer is tenant-scoped, so it reveals nothing across tenants. Measured as bytes and time saved on the pilots' repeated outputs.
- **Streaming publication.** An artifact can be published while later steps run (`artifacts[].when: step:<id>`), overlapping upload with execution; finalization still decides required coverage, and a publication after the attempt's lease is fenced as today.
- **Run-level artifacts.** An authorized client (`artifacts:write`, a new scope bit) may attach files to a run it can operate on, through the existing upload sessions; they are recorded with their uploader and never satisfy a job's declared required artifact.
- **Runner-mode artifacts.** `actions/upload-artifact` and `download-artifact` in a runner-mode job are served by the worker host's endpoint (16.10) into the same tenant-scoped objects and manifests, recorded against the GitHub run and job that produced them, retained under the same classes and quotas, and listed and downloaded through the same API, CLI, MCP and UI; nothing is stored at GitHub. A later job of the same GitHub run reads them from the local store, or through the controller when it runs on another worker.
- **Retention classes.** Deployment-defined named classes (`debug`, `standard`, `evidence`, `release` by default) each with a maximum age and a quota weight; a pipeline names a class, a tenant administrator may pin an artifact (kept until unpinned, still counted). Classes narrow, never extend, the tenant's retention (R01's rule).
- **Downloads.** Whole-artifact archives (`tar` or `zip`) streamed from the manifest with bounded buffers and no temporary file; per-entry range reads; whole-object reads rehashed while streaming as today. Range verification uses BLAKE3's verified streaming only if measured cost allows; otherwise ranges stay unverified and say so.
- **Signed short-lived download URLs.** `GET /dl/<token>`: an HMAC token over `(tenant, artifact, entry or archive, expiry, key epoch)`, minted only for a caller who may read the artifact, valid at most 5 minutes by default (1 hour ceiling), keyed by a sealed secret rotated with the key epoch. Redemption re-checks that the artifact is still retained and the tenant active; it does not re-check the minting session, which is why the life is short. Tokens appear only in URLs handed to the requester, never in logs (the access log records a token digest). Objects evicted to S3 are streamed back through the controller; presigned S3 URLs are an opt-in that exposes the bucket host.
- **Browsing.** The run view lists artifacts by job with class, size and expiry; an artifact opens as a file tree with path search, sizes and digests; text up to 1 MiB and images preview in the page, served as `Content-Disposition: attachment` with `X-Content-Type-Options: nosniff` and a sandboxing CSP, everything else downloads.
- **Access.** API: archive, signed-link minting, pin/unpin, run-level upload. CLI: `artifact download --all --out DIR`, `artifact upload`, `artifact link`. MCP: `list_artifacts`, `get_artifact`, `read_artifact_file` (bounded text, labelled untrusted), `get_artifact_link`; all behind `artifacts:read` and repository authorization.

**Gates.** A 4 GiB archive download holds bounded memory (target ≤ 64 MiB RSS growth in the controller); time to first byte for a local entry p95 < 100 ms on the reference host; a forged, expired, cross-tenant, retired-artifact or old-epoch token is refused with the same `not_found`; digest-first transfer never uploads a body the tenant holds and never reveals another tenant's; S3-evicted downloads verify.

### 16.3 Default tenant storage limits

**What exists.** R01: a deployment cap, a per-tenant quota (`tenant_quota_bytes`, default 0 = unlimited), repository quotas inside it and a run budget; usage is committed objects, open uploads and stamped log bytes; artifacts and uploads past quota are refused (`quota_exceeded`), logs are counted and never refused; platform and tenant administration set policies ([retention](docs/retention.md#policy-at-each-level)).

**What changes.**

- **A default limit.** An unset `tenant_quota_bytes` becomes a sized default instead of unlimited (for example 50 GiB, or a fraction of the data file system when that is smaller), with a separate `personal_quota_bytes` default for personal namespaces; `0` stays available as an explicit "unlimited" set by a platform administrator per tenant. This is a behavior change on upgrade: a [compatibility](docs/compatibility.md) entry, and the upgrade preflight lists tenants already above the new default.
- **Cache counts.** Tenant usage gains classes: `artifacts` (native and runner-mode), `logs`, `uploads`, `remote_cache` (the controller's remote cache store, whose bundles are tenant-scoped), `actions_cache` (runner mode's `actions/cache` entries on worker hosts, enforced, since GitHub's 10 GB per-repository limit no longer applies) and, reported but not enforced, `worker_cache` (native jobs' worker-local caches by tenant, from availability reports; workers keep enforcing their own budgets).
- **Thresholds.** Soft at 80 % and hard at 100 % by default, configurable per deployment and per tenant. Crossing soft: a notice in the UI and API, one notification to tenant administrators (re-armed below 75 %). At hard: the tenant's remote-cache bundles are evicted least recently served first until under the limit; then artifact publication is refused with `quota_exceeded` naming used, limit and the largest classes, recorded as the artifact's failure (a required artifact therefore fails the job, visibly, as today); logs are still counted, never refused, so a tenant can exceed 100 % only by logs, which retention then reclaims.
- **Accounting.** Per-class usage kept by triggers as `tenant_usage` is today; a daily snapshot row per tenant (bounded to 90) for trends; the controller exports per-class totals as metrics without a tenant label by default (cardinality), with a per-tenant breakdown in the API.
- **Display.** Tenant administration shows usage by class and repository against the limit and thresholds, the trend, the largest artifacts, and what expires in the next 7 days; platform administration lists tenants by percentage used and sets overrides.
- **Notifications.** Through the durable mail outbox (`sentinel-mail`) when mail is configured, otherwise in-app only; once per crossing, audited.

R01 stays the mechanism: this adds a default, cache classes, thresholds and notifications on top of the same quota checks and the same refusal path.

**Gates.** Concurrent uploads racing at the limit never exceed it by more than one in-flight charge; eviction never removes a bundle in use; a tenant at hard limit still runs jobs and stores logs; overrides take effect on the next check without restart; upgrade preflight reports correctly on a copy of a populated database.

### 16.4 Web interface on TanStack Start

**Decision.** Replace the Nuxt 4 application (`web/`) with a TanStack Start application, by the owner's decision of 2026-10-22, for a faster and lighter interface closer to Blacksmith's product UX. TanStack Start 1.0 was announced stable on 2026-10-13. The process keeps its name and role: `sentinel-web`, optional, holding no credential or state, rendering as the signed-in person and proxying the controller's routes as one origin ([web interface](docs/web-ui.md)).

**Application model.**

- **Routes.** File-based TanStack Router routes mirroring today's paths (`/t/$slug`, `/runs/$id`, `/runs/$id/logs/$attempt`, `/t/$slug/admin/$section`, `/platform/$section`, the sign-in, setup and email-link pages).
- **Search params.** Validated with a Standard Schema validator on every route that has them (run filters `ref`, `pr`, `sha`, `before`; log deep links `step`, `seq`, `q`); a malformed parameter falls back to the default, never reaches the API unvalidated. The validator library is chosen by measured client bundle cost (Effect Schema if it fits the budget, since Part 22 uses Effect; otherwise a smaller one).
- **Loaders and server functions.** Route loaders call typed server functions (`createServerFn` with input validation) that call the controller API with the browser's own cookie; the API client lives in server-only modules (`*.server.ts`, `createServerOnlyFn`), so no controller address, header logic or upstream URL building reaches the client bundle.
- **Rendering.** Full-document SSR with streaming; per-route SSR mode: `ssr: true` for sign-in, setup, run list, run detail and administration; `ssr: 'data-only'` for the log viewer (data fetched on the server, the windowed DOM built in the browser by the unchanged `logviewer.ts`); `ssr: false` nowhere by default.
- **Live updates.** The `/_stream/run/<id>` and `/_stream/log/<attempt>` server-sent event routes move as server routes with the same event names, ids and payloads, so the browser code and `Last-Event-ID` resumption are unchanged.
- **Security parity.** The proxy allowlist (`classifyProxyPath`), body ceilings, client-address handling and headers move unchanged in behavior; the CSP keeps hashes for inline scripts and no `unsafe-inline` (whether Start's inline hydration data can be hashed per response is the first spike, U09).
- **Components.** An accessible headless component library (React Aria Components is the first candidate) with Tailwind, chosen by U09's measurement of bundle size and the U06 accessibility checks.
- **Deployment.** The Vite plugin with the Nitro Node preset produces `.output/server/index.mjs`, run as today (`node …`, the systemd unit); changing the deployment target later (Bun, another Nitro preset) does not change routes, loaders or server functions.

**Migration.** Strangler, route by route: the new application becomes the front process first and forwards every path it does not yet own to the Nuxt process on loopback (same origin, same cookie), so each view moves alone and is checked against its row of the Views table; when the last row moves, the Nuxt process and `web/` Nuxt code are removed. The parity checklist is the [Views table](docs/web-ui.md#views) plus the step-up, session-ended, shown-once, namespace-switcher, log-viewer and setup-resume behaviors; each item is checked by the browser test before its Nuxt route is deleted.

**Budgets.** Against a committed baseline of the current `sentinel-web` (U08; the 61.5 MiB idle figure in the completion log was never recorded and is not a baseline): shipped JavaScript for the run-detail first load at most half the Nuxt baseline; server render time p95 no worse than the baseline at the same controller latency; idle and after-all-views RSS no worse than the baseline; ten live log streams for 30 s no more CPU than the baseline; log-view work per scroll jump within the U01 record's range. Browser test coverage (`web/test/ui.mjs` structure, keyboard, contrast, layouts, live, role changes, large log, account, onboarding) is kept and extended with the setup wizard seed.

**Blacksmith-like additions after parity.** Blacksmith's run history offers log search across runs, run comparison and per-job metrics, and its analytics show job duration percentiles with per-step breakdowns ([16.7](#167-sources-for-section-16)). Sentinel equivalents need controller routes first: per-job duration percentiles over the last N runs from attempt phase timings, a two-run phase comparison, and bounded literal log search across a repository's recent runs. They follow parity (U16), each with its own API task.

### 16.5 Guided GitHub Actions migration

**Reference.** Blacksmith's Migration Wizard opens a pull request that changes the `runs-on:` labels of the selected workflows; its GitHub App asks Contents write, Workflows write and Pull requests write for that, and the PRs stay subject to branch protection; its GitHub integration covers organizations only ([16.7](#167-sources-for-section-16)). With runner mode ([16.10](#1610-github-actions-runner-mode)) Sentinel does the same: the default migration swaps `runs-on:` labels and changes nothing else. Translating workflows into `.sentinel.yml` is the optional "go native for full speed" path, offered per workflow, never the default.

**Flow, in the web interface.**

1. **Connect.** The existing GitHub App binding (G01), with the runner-mode permissions of 16.10 when runner mode is on. Writing to repositories needs Contents, Pull requests and Workflows write; the same one App asks for them only when a tenant starts a migration, and the tenant can withdraw them afterwards (as with runner mode's permissions, setup is refused naming what is missing). Personal namespaces are supported, unlike Blacksmith.
2. **Pick repositories** from the tenant's bound ones.
3. **Analyze.** A bounded, deterministic analyzer in Rust (`sentinel-pipeline`, the same YAML limits) reads `.github/workflows/*.yml` at the default branch's pinned SHA and builds an inventory: triggers, jobs, matrices, `runs-on`, `uses:` actions with versions, `container:`/`services:`, secrets and variables referenced, permissions, concurrency, caches, artifacts. For runner mode, each job's `runs-on` is mapped by a versioned rule table to a Sentinel label (hosted Ubuntu and Windows labels and Blacksmith labels to the class with the same CPUs and OS; arm64 to `-arm`), or kept, with the reason (macOS, GPU, a label Sentinel has no class for, a job needing Docker where only container workers exist). For the optional native path, each construct is classified translatable, translatable with a stated change, or unsupported. No model is involved; Part 22 may suggest, the compiler decides.
4. **Preview.** The page shows, per workflow, the `runs-on` diff and the jobs that stay on GitHub's runners with their reasons. For the native path it shows the generated `.sentinel.yml` (deterministic, from the inventory and the [recipes](docs/recipes.md), validated by `pipeline validate`), the job-by-job mapping and the secrets to provision (names only).
5. **Open a pull request** on a `sentinel/migrate` branch with the App's migration permissions; never a push to the default branch. Re-running updates the same PR.
6. **Shadow.** The PR first adds, for each migrated job, a non-required copy with the Sentinel label (the original job unchanged), so both run on the same SHAs while GitHub's runners stay authoritative. A parity view compares conclusions, test counts (JUnit/Go JSON where reported) and durations per job pair from the Actions jobs and steps API (p50/p95 over the shadow window, with sample counts). On the native path the shadow is Sentinel's own `sentinel / <job>` checks.
7. **Switch.** In runner mode the job names, and so the required checks, do not change: the switch is the PR update that drops the copies and swaps the originals' labels, and branch protection stays as it was. On the native path Sentinel reads branch protection and rulesets, shows the exact change (add `sentinel / ci`, remove the replaced checks) and a person applies it, or, only with an extra opt-in App permission, Sentinel does; then a second PR disables the replaced workflow jobs.
8. **Rollback.** One action opens the revert PR (labels back, or workflows re-enabled) and, on the native path, shows or applies the required-check change back; shadow mode can be re-entered at any time. Every step is audited.

**Gates.** On the three pilots: every job of the inventoried workflows classified with no "unknown"; the runner-mode PR changes only `runs-on:` lines; the pilots' unchanged workflows pass on Sentinel labels; shadow parity reports exist for at least one week of pushes per pilot; switch and rollback each complete and leave GitHub settings exactly as the preview said; native pipelines, where generated, validate. Time from "Connect" to the first shadow run is measured and published.

### 16.6 AI assistance

**Reference.** Blacksmith's documented AI and agent features are [code]smith (a cloud coding agent that reads failed GitHub Actions logs, pushes fixes until checks pass and supports external MCP servers), Testboxes for agents running CI commands, an agent-oriented CLI, and Proof (private beta); its Test Analytics parses JUnit and posts failed tests on the PR. AI root-cause summaries, an AI log assistant and flaky-test detection were **not found** in its documentation as of 2026-10-22 ([16.7](#167-sources-for-section-16)). Sentinel's deterministic diagnostics (X01–X03) remain the authority; AI adds advisory text on top.

**Stack.** A separate optional TypeScript process, `sentinel-ai`, in the same pnpm workspace as the web interface, written with Effect 4. Effect 4.0.0 is stable (npm `latest` 4.0.5 when checked); its AI modules are `effect/ai/*` (the `effect/unstable/ai` path of the 4.0 betas was removed) and are tagged `@stability unstable`, which permits breaking changes in minor releases; the provider packages `@effect/ai-openrouter`, `@effect/ai-openai` and `@effect/ai-anthropic` are at 4.0.5 and count as unstable too, and `@effect/ai-openai-compat` is listed in the Effect README (its version was not checked). Consequences: exact version pins (no ranges), and Sentinel's own `Assistant` interface in front of `LanguageModel`, so an upstream minor change touches one module.

**Providers.** Behind one provider interface:

| Provider | Data leaves the host | Notes |
|---|---|---|
| OpenAI-compatible local endpoint (Ollama, vLLM, or a LiteLLM gateway) | no, when on loopback or a private network | Ollama's compatibility layer lacks `tool_choice` and logprobs; vLLM's API key protects only its `/v1` routes, so it belongs behind a proxy |
| OpenRouter (default hosted provider) | yes | one key for many models; Sentinel always sends `provider.zdr: true` and `data_collection: deny` and enforces them, not the request author; no inference markup, a 5.5 % fee on purchased credits (standard tier) |
| Direct provider APIs (Anthropic, OpenAI) | yes | for an organization with its own contract and data terms |

Recommendation: the deployment default is **off**. For fully local operation, an OpenAI-compatible local endpoint (vLLM for throughput, Ollama for a single host). For hosted models, OpenRouter as the default as requested, with zero data retention enforced; direct provider APIs when an organization has its own agreement. LiteLLM is optional: Sentinel enforces its own budgets, so a gateway is needed only for an operator's own reasons.

**Policy.**

- **Opt-in.** A platform administrator allows AI and the providers per deployment; a tenant administrator enables it per tenant and chooses a data policy: `local_only` (only allowlisted private endpoints), `zero_retention` (providers that honor ZDR), or `provider_terms`. Disabled is the default and takes effect at once: queued requests are dropped.
- **Redaction before any prompt.** The controller, not `sentinel-ai`, builds a bounded evidence bundle (default 32 KiB) from already-redacted stored logs and diagnostics, applies the attempt's registered secret values again and pattern scanners (Sentinel and GitHub token prefixes, PEM blocks, cloud key formats, JWTs), and serves it to `sentinel-ai` through `GET /attempts/{id}/ai-context`. `sentinel-ai` never holds a secret value, a source credential or a whole log.
- **Budgets.** A per-tenant monthly token and cost budget in a controller ledger: each request reserves its maximum (input bytes plus `max_tokens`) before the call and settles from the provider's reported usage after; a request that does not fit is refused, not queued. Per-request input and output caps; a per-tenant concurrency limit.
- **Caching.** An analysis is keyed by evidence digest, prompt template version and model; a rerun with the same failure fingerprint (normalized failed step, test identity and error lines) reuses it, marked reused.
- **Failure isolation.** AI never blocks a check, a run, a dispatch or a log: requests are durable rows with a deadline, processed asynchronously; timeouts, provider errors and budget refusals end as `unavailable`; a circuit breaker per provider; outputs never change outcomes or check conclusions.
- **Output contract.** Responses are decoded against a schema; every claim cites evidence IDs from the bundle, and citations that do not exist are dropped; text is labelled inference; analyses expire with the attempt's logs.

**Features.**

1. **Failure analysis** on request or automatically for failed required jobs (per-tenant setting): a short root-cause summary under the deterministic failure summary, with citations.
2. **Flaky tests**, deterministic first: per-test outcomes persisted from JUnit and Go JSON reports (bounded per repository, retained like logs); a test that failed and then passed on a rerun of the same SHA is a flaky signal; flake rates per test over a window, listed in the UI and API. AI only summarizes a flaky test's failure messages.
3. **Log search assistant**: a natural-language question becomes a bounded plan of existing indexed literal searches and failure-context reads; the model sees only those bounded results; every answer links real lines.
4. **Migration suggestions** (16.5): proposed translations for constructs the rule table marks unsupported, always validated by the compiler and shown as suggestions.

**Authorization and MCP.** User-initiated requests carry the requester's identity: `sentinel-ai` calls the API with a request-scoped delegated token the controller mints (the requester's scopes intersected with read-only, ten minutes, bound to the request), so it can read nothing the requester cannot. External agents keep using MCP ([MCP](docs/mcp.md)); analyses and flaky-test lists are added as read-only MCP tools labelled inference. Sentinel never forwards a Sentinel or upstream token to a model provider, and model output is untrusted data wherever it appears, including when an MCP client reads it.

**Evaluation and gates.** An evaluation set from seeded failures on the three pilots and the X08 100 MiB noisy fixture: the share of analyses citing the line with the actual error; citation validity (100 %, enforced by the schema); a canary-secret test asserting at a recording fake provider that no registered secret, token prefix or PEM block ever reaches a prompt; cost and latency p95 per analysis; a regression gate per model and prompt version. A provider outage changes no run's timing (measured against the B03 budgets with AI enabled and its provider failing).

### 16.8 MicroVM execution on KVM hosts

**Why.** Rootless containers share the host kernel, so they are a boundary for trusted code only. A microVM per job gives each job its own kernel: the prerequisite for hostile fork pull requests (I09), and one of the two ways to run Windows jobs from a Linux host. Blacksmith's documentation says both its Linux and Windows jobs run in ephemeral Firecracker microVMs on its own bare-metal hosts, quotes boots under 3 s, bases its Windows runners on GitHub's Windows Server 2025 image and offers only limited nested virtualization inside them ([Blacksmith runners](https://docs.blacksmith.sh/blacksmith-runners/overview.md)). Upstream Firecracker has no UEFI and documents Linux hosts and Linux guests only ([design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)), and Blacksmith's documentation does not name the VMM behind its Windows runners. A read-only probe job observed both (2026-10-22, a private workflow on `blacksmith-2vcpu-ubuntu-2404` and `blacksmith-2vcpu-windows-2025`; one run, so observations, not benchmarks, and not Sentinel evidence):

| Observed | Linux runner | Windows runner |
|---|---|---|
| VMM | Firecracker: no DMI strings, no ACPI tables, no EFI, `pci=off`, devices passed as `virtio_mmio.device=` on the kernel command line, hypervisor ID `KVMKVMKVM` | **Cloud Hypervisor**: SMBIOS manufacturer `Cloud Hypervisor`, model `cloud-hypervisor`, firmware `CLOUDH - 1` (its UEFI build), UEFI boot |
| Guest | kernel 6.6.141, ext4 root on virtio-blk (`/dev/vda`, 153 GiB) plus ten empty virtio-blk slots, one virtio-net, a balloon; CPU brand masked to `AMD EPYC` (a CPU template) | Windows Server 2025 Standard **Evaluation** (build 26100), virtio-pci network, SCSI (200 GiB) and RNG with Red Hat's virtio-win drivers 100.100.104.271; host CPU AMD EPYC 4565P |
| Boot | kernel started 5 s after the run was queued, the job 9 s after | kernel started 4 s after the run was queued, the job 18 s after (uptime 23 s at probe time): a fresh boot per job, not a long-lived restored snapshot |
| Nested virtualization | `/dev/kvm` present in the guest | Hyper-V disabled; none |

The split this plan decided — Firecracker for Linux guests, Cloud Hypervisor with its UEFI firmware and virtio-win for Windows guests — is what those two runners ran in that run, and the Windows guest booted evaluation media. Their queue → job times, about 9 s (Linux) and 18 s (Windows), both from fresh boots, are the comparison reference Sentinel's microVM path must beat; they are one run on another vendor's hardware, recorded as reference, never as Sentinel evidence. Sentinel's gate is its own B03 budget on the snapshot-restore path (M06), not their figure.

**Host prerequisite, measured.** Every candidate VMM needs hardware virtualization: `/dev/kvm` on a bare-metal host, or a guest with nested virtualization. The `reference-host` verification guest had neither when checked on 2026-10-22: no `svm` CPU flag, no `kvm` module and no `/dev/kvm`. MicroVM and Windows-guest work therefore runs on an x86_64 KVM host; non-KVM workers keep running rootless containers. A worker reports `kvm` (and `kvm.nested` when it is itself a guest) as a capability, so placement never sends a microVM job to a host that cannot boot one.

**Runtime selection** (owner decision, 2026-10-22). Each worker detects what its host can run and picks its default executor from that; the operator can override it per worker (`isolation = "container" | "microvm"`), and a pipeline can ask for one with `runs_on.isolation`. Detection opens `/dev/kvm` as the worker account and creates a throwaway VM (`KVM_CREATE_VM`), so a device the account cannot use counts as absent; on Windows it asks whether the Hyper-V/Windows Hypervisor Platform is usable.

| Host | Hardware virtualization | Default executor | Linux jobs | Windows jobs |
|---|---|---|---|---|
| Linux | yes (`/dev/kvm` usable) | microVM | Linux guest (Firecracker) | Windows guest (Cloud Hypervisor, restored from a snapshot; Firecracker cannot boot Windows) |
| Linux | no | rootless Podman | container | not available |
| Windows | yes (hypervisor platform usable) | native job object for Windows jobs | Linux guest (WSL2 or Hyper-V microVM) | native |
| Windows | no | native job object | not available: Podman on Windows itself runs Linux in a WSL2/Hyper-V VM, which needs the virtualization that is missing | native |

The worker advertises what it can run (`os.linux`, `os.windows`, `isolation.microvm`, `isolation.container`, `isolation.native`, `kvm`, `kvm.nested`) and placement matches a job's `runs_on.os` and `runs_on.isolation` against it, explaining a refusal. The microVM default stands on KVM hosts; M08 measures and publishes its overhead against rootless Podman on the same host, and a regression beyond the B09 gate is a bug to fix, not a reason to change the default silently.

**Verification host classes.** The public `kvm-host` label denotes an x86_64 bare-metal verification host with `/dev/kvm`, `kvm_amd` and nested virtualization enabled. `reference-host` and `arm64-host` denote virtualized x86_64 and arm64 workers without hardware virtualization, so they run containers only. Benchmark records retain the measured CPU, memory and kernel provenance under these anonymized labels. Accounts, addresses and unrelated host services are not published; tests use capped unprivileged slices, and fault injection stays inside Sentinel's own processes, network namespaces and loop devices.

**VMMs** (owner decision, 2026-10-22, matching the probe above): Linux guests on Firecracker with its jailer, virtio-mmio devices, no PCI, no firmware and a CPU template; Windows guests on Cloud Hypervisor with its own UEFI firmware (CLOUDHV), virtio-pci devices and virtio-win drivers; Windows Server evaluation media as the verification image. No QEMU: it is too heavy for many VMs per host and endangers the performance targets. Cloud Hypervisor shares the rust-vmm crates with Firecracker, so its device model is close to Firecracker's.

| VMM | Guests | Strength | Known cost |
|---|---|---|---|
| Firecracker (+ jailer) | Linux | smallest device model (virtio-mmio net/block/vsock, kernel booted directly, no firmware), CPU templates, snapshots, fast boot | no PCI, no GPU, no UEFI, no Windows; a kernel and rootfs per image; may expose nested KVM to the guest |
| Cloud Hypervisor | Windows (UEFI, CLOUDHV); Linux only if M02 says so | virtio-pci, virtiofs, snapshots; one VMM could serve both OSes | larger surface than Firecracker; Windows needs virtio-win drivers; no nested virtualization for Windows guests |

M02's Linux measurements are recorded under **As built** below: Cloud Hypervisor does not match Firecracker for Linux guests, so the split stands. The Linux part of M02 is assessed and closed by the records in `bench/m02-boot.jsonl` (checked against the file on 2026-10-29: every figure under **As built** matches its 200 samples and ten idle-memory samples; each record is stamped with the host's kernel, CPU model, governor, load and CPU pressure and the SHA-256 of the VMM, kernel, initramfs and root file system, and the restore record carries its own note that it is boot-only). What remains of M02 is the Windows-guest measurement, which belongs to M07 (Windows guests are not required for the current release), and the capacity measurement at the pilot allocation, which closes with the capacity item. The restore distribution is boot-only and does not prove M06's per-attempt copy-on-write restore.

**Guest images.** Linux: an ext4 root filesystem on virtio-blk built from the job's pinned OCI image digest (cached per digest, read-only, with a per-attempt writable overlay or block clone), a pinned guest kernel booted directly, and further virtio-blk devices for the workspace and caches; the probe's layout (a root disk plus spare block slots) is the same shape. Windows: a sysprepped evaluation image on a virtio-pci SCSI disk, with the virtio-win drivers and the agent installed as a service.

**Nesting** (design limitations). A Firecracker Linux guest may be offered `/dev/kvm` (nested KVM), as the probe's Linux guest was; Sentinel does not expose it by default, and the hostile-fork pool (M09) decides explicitly whether to, defaulting to no. A Windows guest gets no nested virtualization: no Linux containers or WSL2 inside Windows jobs.

**Execution model.** One microVM per attempt, booted (or restored) from the guest image above; a small in-guest agent over vsock that runs steps and streams frames into the existing log, spool and redaction path, so the worker protocol and the controller do not change. Cancel asks the agent, then kills the VM; a lease loss kills the VM. Warm start through VMM snapshots of a booted guest, restored copy-on-write: the warm path for Linux guests and the only path for Windows guests. Network through a per-VM tap device with nftables rules giving the container job network's policy (none, or operator-granted egress without the host, the link port or metadata addresses). Windows guests are viable only with snapshot restore: a cold Windows Server boot takes tens of seconds even under Cloud Hypervisor (the probe's fresh-boot job started 18 s after queueing). The sysprepped image is booted once, snapshotted, and restored copy-on-write per attempt; snapshot restore (M06) is therefore a prerequisite of Windows guests (M07), not an optional optimization. The image's licence is the operator's (Windows Server evaluation media for verification).

**As built** (2026-10-24; departures from the decisions above are marked).
- *Versions, pinned:* Firecracker v1.17.0 (its published checksum verified), Cloud Hypervisor v53.0 static with its UEFI firmware from edk2 `ch-811ce5ea35` (no checksums published, so their SHA-256 are recorded at download), guest kernel Linux 6.18.52 with Firecracker's own CI guest configuration of the same release, which also boots under Cloud Hypervisor through PVH. `bench/microvm/build-kernel.sh` rebuilds it in a throwaway rootless container, so the host needs no kernel build packages.
- *No jailer (departure).* The jailer needs root (chroot, uid switch, cgroup and network setup), and the worker is rootless by design, as are the machines' rules: no setuid helpers or sudo rules are added. Its job is done with what the worker account has: a user namespace from `podman unshare` (Podman's setuid id-map helpers, so Ubuntu's AppArmor restriction on unprivileged user namespaces does not bite), a fresh network and mount namespace per VM, a user systemd scope per VM (`sentinel-vm-<attempt>`) that caps CPU and memory and names the VM for cleanup, and Firecracker's own seccomp filters. The VMM also runs in a chroot that is its VM directory, with the few files it opens bind-mounted in by the launch script in the VM's own mount namespace (root of the rootless user namespace, so no setuid helper is added): that is the jailer's confinement without its uid switch, cgroup and pid namespace, and it is what makes the drive paths saved in a snapshot (M06) the same for every VM and valid wherever the data directory is.
- *Guest boot.* The pinned kernel with an initramfs whose `/init` is the guest agent (`crates/sentinel-agent`, a static musl binary); the worker writes the initramfs from the agent binary. `/dev/vda` is the job image as a read-only ext4 file built once per image from the pulled OCI image (`podman unshare` + `podman image mount` + `mkfs.ext4 -d`, owners preserved) and cached; `/dev/vdb` is the attempt's scratch disk, sized to the job's disk reservation. The agent mounts the image under a writable overlay on the scratch disk and gives it `/proc`, `/sys`, `/dev` and a 1 GiB `/tmp`, as a container has; steps run as root chrooted into it (the VM is the boundary). The image's `ENV` is applied to steps, as `podman exec` applies it.
- *Files in and out (departure from virtio-blk workspace and cache devices).* Firecracker has no shared file system, and building block images of the workspace per attempt needs tools a rootless worker lacks. The workspace and mounts go in as tar streams over vsock, and what the host reads afterwards comes back the same way: the declared artifact paths and every writable cache mount. M08 measures this cost against Podman; block-device caches are the optimization if it is too high.
- *M02, measured* (`bench/m02-boot.jsonl`, 2026-10-24, `kvm-host` CCD1, the pinned kernel and initramfs, a busybox image disk, 1 vCPU and 512 MiB, n = 200 each, VMM start -> the guest agent's answer over vsock): Firecracker cold boot p50 120 ms / p95 128 ms, 153 / 163 ms inside the rootless sandbox (`podman unshare` and a fresh network namespace: about 33 ms); Firecracker snapshot restore p50 11.5 ms / p95 12.0 ms (boot timing only; every restore reused the base scratch file and paths, so this is not M06 evidence); Cloud Hypervisor cold boot of the same guest p50 291 ms / p95 318 ms (327 / 358 ms sandboxed). Idle PSS per VM, ten together: Firecracker 57 MiB, Cloud Hypervisor 67 MiB. Outcome: Cloud Hypervisor does not match Firecracker for Linux guests (about 2.4 times the cold boot, 17 % more memory), so the split stands: Firecracker for Linux guests, Cloud Hypervisor for Windows guests only. At the pilot allocation (10 CPUs, 26 GiB per job) the capacity calculation is four such VMs by memory and two by CPU without overcommit; this is arithmetic, not a measurement; the full-allocation capacity measurement is the capacity item's, not the Windows-guest M07's.
- *Agent protocol.* Length-prefixed postcard frames over the hybrid vsock (`sentinel_protocol::agent`, version 3): put and get tar streams, exec with streamed output (as the image's `USER`), signal one command or every process, kill strays, OOM count, shutdown, `Resume` (fresh entropy and the host's clock for a restored guest), `Wipe` (a step's secret directories), `WaitIdle` (a polite cancel's check) and `MemoryLimit` (the cgroup the steps share). The agent serves several connections at once, so a cancel signals the guest without the attempt's stream.
- *Network (M05, as built 2026-10-28).* No interface unless the worker grants egress (`job_network = "egress"`). Granted, the VM's own network namespace holds a tap (10.211.0.1/30) that Firecracker attaches as the guest's `eth0` (10.211.0.2, set by the agent from the kernel command line), nftables rules loaded in that namespace before the VMM starts (forwarding closed; the guest may open connections outward as its own address except to loopback, link-local and metadata ranges, every address of the host and the controller's link endpoint; all IPv6 and the namespace itself closed; masquerade behind the namespace) and `pasta` attached from outside with the container policy's `--no-map-gw` and no port forwards, which carries the outbound connections through the worker account's sockets and answers the guest's resolver address with the host's. Departure from "the nftables rules on the host": the rules live in the VM's namespace, so a rootless worker needs no host interface, bridge or rule and nothing outlives the VM's scope. Rule generation is `net::Policy::rules`; [executor](docs/executor.md#network-m05) lists the refused ranges and the prerequisites (`ip`, `nft`, `pasta`, `/dev/net/tun`).
- *Snapshot warm start (M06, as built 2026-10-28).* A VM restores from a Firecracker full snapshot of a booted, idle guest of its shape (image, vCPUs, memory, scratch size, network); the memory file is mapped privately (copy-on-write in memory), the scratch disk is a per-attempt clone of the snapshot's (reflink or data-extent copy), the snapshot is built by the first VM of the shape from a template VM and named by every input it depends on, a restore sends the agent fresh entropy and the host's clock, and any failure falls back to a cold boot of the same attempt. The paths saved in a snapshot are the same for every VM and name nothing of the worker's data directory, because each VMM runs in a chroot that is its VM directory (the kernel, initramfs, image, `/dev/kvm`, `/dev/net/tun` and the snapshot directory bind-mounted in by the launch script), so a snapshot restores wherever the data directory is. Departure from "per-attempt copy-on-write of the whole VM": disk clones are file-level, and guests above 8 GiB boot cold because their memory file would be written whole. [Executor](docs/executor.md#snapshot-warm-start-m06) has the details. What is measured: unit and gated tests for correctness and cleanup; the ready-to-first-process distribution on the restore path and the cold figure beside it are the benchmark of the gate below and are not yet recorded (`tests/microvm.rs` carries the worker-side harness, `the_cold_and_restored_start_to_first_process_distributions`, which attributes the time per start; the published figure is the end-to-end one of `bench/b03-latency.py` against a microVM worker on a quiet KVM host).

**Gates.** On the KVM host: ready -> first user process p95 < 2 s on the snapshot-restore path for Linux and Windows guests (the B03 budget, unchanged), well under the probe's 9 s and 18 s reference, with the cold-boot figure published beside it; memory overhead per idle VM; the pilots' Linux lanes pass in a microVM with the same assertions, wall time compared with rootless Podman on the same host and caps; a guest cannot reach the host, the control endpoint or another VM; cancel -> VM gone p95 < 2 s; nothing left after a worker crash.

### 16.9 Re-audit and rework of earlier parts

Parts 01-14 were built over several months by several models and agents, many of them weaker than those now available, so the owner expects rework, not only review; the 2026-10 cleanups and the 2026-10-24 current-tree rebaseline found contracts that drifted, untested failure paths, stale completion/open-item states and hot-path costs nobody measured ([open items](TODO.md#open-items)). Part 24 starts with the confirmed authorization/admission and durability defects before further feature optimization. Before Part 15 builds on them, each area is reviewed again against `AGENTS.md`'s rules: the cheapest correct implementation for the access pattern, bounded resources, durable transitions, tenant isolation, tests that exercise behavior and failure paths rather than mirror code, docs that match the code. A review produces findings with file and line, each either fixed with a test in the same task or filed as its own task; nothing is rewritten for style alone, and a rework that changes a versioned contract follows [compatibility](docs/compatibility.md). Reviews read code; a claim about cost is settled by a measurement on the host pinned by the applicable contract, never by reasoning alone. Part 24 also reconciles migration 54 and the already-landed Linux microVM path, and closes only after Part 14, Q13, B09 and B11.

### 16.10 GitHub Actions runner mode

**Decision** (owner, 2026-10-22). Moving a repository from GitHub Actions or Blacksmith to Sentinel must be one label change, not a CI rewrite. Sentinel therefore gains a runner mode, planned first among the migration work (`TODO.md` Part 25, before Part 21): GitHub keeps orchestrating the workflow, and Sentinel supplies the machine for jobs whose `runs-on:` names a Sentinel label. This is Blacksmith's model (`runs-on: blacksmith-<n>vcpu-ubuntu-2404` / `-windows-2025`; [16.8](#168-microvm-execution-on-kvm-hosts) records what its machines run). Sentinel does not interpret Actions YAML in this mode: the official `actions/runner` does. Executing Actions syntax natively is out of scope. Native `.sentinel.yml` stays the full-speed mode, with Sentinel's own scheduling, caches, logs, diagnostics and Checks.

**What GitHub provides** ([16.7](#167-sources-for-section-16); recheck against the pinned API version before implementing):

- **Just-in-time runner configuration.** `POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig` and `POST /orgs/{org}/actions/runners/generate-jitconfig` take a runner `name`, a `runner_group_id`, 1 to 100 `labels` and an optional `work_folder`, and return the runner object and an `encoded_jit_config` that is passed to the runner application at start. GitHub's runner reference describes these as ephemeral just-in-time runners, and an ephemeral runner is assigned one job and then de-registered by the service.
- **`workflow_job` webhooks** with the activities `queued`, `waiting`, `in_progress` and `completed`; a GitHub App receives them with at least read access to the Actions repository permission. GitHub's autoscaling guidance builds on the `queued` event and warns that scaling on webhooks depends on their timely delivery; for larger volumes it points to Actions Runner Controller or its open-source Scale Set Client.
- **Registering runners as a GitHub App** needs the `administration` repository permission, or the `organization_self_hosted_runners` organization permission.
- **Network.** A self-hosted runner needs outbound HTTPS to `github.com`, `api.github.com` and `*.actions.githubusercontent.com`, and for logs, artifacts and caches to `results-receiver.actions.githubusercontent.com` and `*.blob.core.windows.net`.
- **Updates.** Runners update themselves by default; with updates disabled, a runner must be updated within 30 days of a release or the service stops queueing jobs to it. `actions/cache` needs runner 2.231.0 or newer for the cache service it has used since 2025-02-01 (v5 needs 2.327.1).
- **Public repositories.** GitHub recommends self-hosted runners only for private repositories, because a fork pull request can run code on the runner; just-in-time runners reduce that risk only when the environment is clean for each job.

**Model.**

1. **Permissions and binding.** Runner mode needs permissions the base App does not hold (Actions read for `workflow_job`; organization self-hosted runners, or repository administration for personal namespaces, which have no organization). Decided 2026-10-22: they join the base App, as Blacksmith's single App holds them, so an installation stays one click and one binding; `actions` read and `organization_self_hosted_runners` write for organizations, repository `administration` write only where a personal namespace has no organization to register runners in. An operator who wants checks alone leaves runner mode off and the installation never needs them: the controller asks for the runner permissions only when runner mode is enabled for a tenant, and refuses runner-mode setup, with the missing permission named, while they are not granted. The installation → tenant binding (G01) is unchanged. A job is served only when its repository is bound to that tenant and the label's pool is one the tenant may use; tenant ownership is never inferred from the payload.
2. **Labels.** `sentinel-<n>vcpu-ubuntu-2404`, `sentinel-<n>vcpu-windows-2025`, and `sentinel-<n>vcpu-ubuntu-2404-arm` for arm64 workers (`arm64-host`-class). A label names a resource class (n CPUs, with memory and disk per class from deployment configuration) and the OS; the tenant's binding maps it to a pool. A label Sentinel does not define is ignored, so a job meant for another runner never starts a Sentinel machine.
3. **Demand.** A `queued` event enters the existing durable intake (deduplicated by delivery, acknowledged after commit) and becomes a Sentinel job of the label's class, placed by the same scheduler (fairness, reservations, pools, fenced leases). Because GitHub assigns queued jobs to any idle runner with matching labels, Sentinel treats `queued` events as demand per label set rather than as a binding to one job, and reconciles: a missed event is caught by a bounded reconciliation pass, and an idle runner left without work is de-registered and its sandbox destroyed after a short bound. Whether webhooks plus reconciliation or the scale-set protocol behind the Scale Set Client is the better demand source is decided by measurement (AR02).
4. **Execution.** When the job is leased, the controller requests the JIT configuration and delivers it to the worker over the worker link as a sealed, single-use credential. The worker starts a fresh sandbox — rootless Podman on a host without KVM, a Firecracker (Linux) or Cloud Hypervisor (Windows) microVM on a KVM host ([16.8](#168-microvm-execution-on-kvm-hosts)) — from a runner image, starts the pinned official `actions/runner` inside it with that configuration, and destroys the sandbox when the runner exits after its one job. The lease, timeouts, cancellation and reconciliation are the existing ones; GitHub's own cancel ends the runner, and the `completed` event or the runner's exit releases the reservation.
5. **What Sentinel records.** Lifecycle and timing (event received, leased, sandbox ready, runner online, job started and finished from the `workflow_job` events), resource use and infrastructure failures. Job logs, annotations, artifacts and check results stay on GitHub; Sentinel captures no job output, so it never stores what the runner masks with secrets it does not know.

**Docker inside a job.** `container:`, `services:` and Docker container actions need a Docker daemon on the runner. A microVM guest can run one; a rootless Podman sandbox cannot offer a daemon without nesting. Runner-mode jobs that need Docker therefore require a microVM label class, and the analyzer (16.5) says so; Windows guests have no nested virtualization, so no Linux containers there ([16.8](#168-microvm-execution-on-kvm-hosts)).

**Performance in runner mode.**

- **Cache and artifacts on local disk, transparently** (decided 2026-10-22: cache as fast as Blacksmith's, and artifacts never stored at GitHub). `actions/cache`, the `setup-*` actions' caching and `actions/upload-artifact`/`download-artifact` keep working unmodified, but their bytes go to Sentinel's cache store and artifact store (Part 18) on the worker host's NVMe instead of GitHub's storage: inside each runner sandbox, DNS resolves the Actions cache and artifact service hosts to a Sentinel endpoint on the host, and a certificate authority minted per sandbox and trusted only inside it lets that endpoint terminate TLS for those names; every other GitHub host passes through untouched, so the runner's control traffic is never intercepted. The endpoint speaks the services as the open-source clients at a pinned version call them (GitHub publishes the actions and their limits, not the service protocols), and answers anything it does not implement by refusing, never by forwarding job bytes to GitHub. GitHub's 10 GB per-repository cache limit no longer applies; Sentinel's tenant quotas (Part 19) do. If a protocol detail blocks transparent serving for a client version, the fallback is a drop-in `sentinel/cache` or `sentinel/upload-artifact` action, a one-line workflow change stated as such. Scopes keep Sentinel's rules (tenant, repository, trust, platform), and a fork-PR job never writes a trusted scope.
- **Docker layer cache.** A registry pull-through cache on each worker host for the registries jobs pull from, wired into the sandbox's container engine, so repeated `docker pull` and `container:` images come from local disk.
- **Warm images.** Runner images carry the toolchains of GitHub's hosted runner images ([actions/runner-images](https://github.com/actions/runner-images)) for Ubuntu 24.04 and Windows Server 2025, or a documented subset where size or licensing makes the full set impractical; the subset is published, and a job that needs a missing tool fails visibly, never silently on another version.
- **Warm starts.** On microVM hosts, snapshot restore (M06) of a booted guest with the runner installed and idle, so the per-job cost is restore plus runner registration.
- **Measurement.** Queue → job (the `queued` event to the job's `in_progress`) and runner-mode overhead, on the pilots' own workflows, against the Blacksmith probe's reference (about 9 s Linux and 18 s Windows from fresh boots, one run; [16.8](#168-microvm-execution-on-kvm-hosts)) and against GitHub-hosted runners measured the same way. Those are comparison references, never Sentinel evidence. Gate: the B03-style budgets on the restore path, from event receipt to the runner online (Sentinel's part) p95 < 2 s, with GitHub's assignment time reported separately.

**Security.**

- The JIT configuration is a credential: requested only when a lease exists, held in memory, delivered sealed to the one worker, passed to the runner without touching a log, an environment listing or the job's workspace, and never retried onto another worker; registration failures are logged without it.
- One ephemeral runner per job, destroyed after that job; nothing writable survives into the next.
- Fork pull requests run only on the hostile-fork pool (M09) when a tenant opts in; otherwise Sentinel does not provision a runner for them (the job stays queued on GitHub until its own timeout, which the tenant can avoid with GitHub's fork-approval settings).
- Egress is the operator's policy, and runner mode needs it by nature (the runner talks to GitHub): runner-mode pools run with `job_network = "egress"`, still without a route to the worker host, the controller's link port or metadata addresses.
- Secrets stay GitHub's. Sentinel never receives Actions secrets; they exist only in the runner process inside the sandbox for the job's life.

**Gates.** A pilot's unchanged workflow passes with only `runs-on:` changed, on Linux (container and microVM) and Windows (guest); queue → job and overhead distributions published against the references above; the restore-path budget met; no JIT configuration in any log, bundle or record; every sandbox gone after its job, a cancel and a worker crash; fork-PR jobs refused or confined as configured.

### 16.7 Sources for section 16

Inspected 2026-10-22; recheck before implementation.

- GitHub Actions runner mode: [self-hosted runners REST API](https://docs.github.com/en/rest/actions/self-hosted-runners) (just-in-time configuration: `generate-jitconfig` for repositories and organizations, its body and `encoded_jit_config`), [webhook events and payloads](https://docs.github.com/en/webhooks/webhook-events-and-payloads) (`workflow_job` activities and the Actions read permission), [self-hosted runners reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners) (ephemeral and just-in-time runners, updates within 30 days, network domains), [autoscaling with self-hosted runners](https://docs.github.com/en/enterprise-cloud@latest/actions/hosting-your-own-runners/managing-self-hosted-runners/autoscaling-with-self-hosted-runners) (`workflow_job` autoscaling, webhook-timeliness caveat, Scale Set Client, the App permissions for registering runners), [secure use reference](https://docs.github.com/en/actions/reference/security/secure-use) (self-hosted runners and public repositories), [`actions/cache`](https://github.com/actions/cache) (the cache service since 2025-02-01, runner minimums 2.231.0 and 2.327.1 for v5, 10 GB per repository; no public protocol document), [`actions/runner-images`](https://github.com/actions/runner-images) (the hosted images' toolchains). The cache service's wire protocol is not documented by GitHub as a public API; AR06 takes it from the open-source client at a pinned version.

- MicroVMs and hosts: [Blacksmith runners](https://docs.blacksmith.sh/blacksmith-runners/overview.md) (Linux and Windows jobs in Firecracker microVMs) and [Firecracker design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md) (Linux hosts and guests). Verification-host capabilities come from read-only local probes recorded above.

- Blacksmith: [quickstart](https://docs.blacksmith.sh/introduction/quickstart) (GitHub organizations only; Migration Wizard or manual `runs-on:` edits), [GitHub App permissions](https://docs.blacksmith.sh/blacksmith-administration/github-app) (Contents, Workflows and Pull requests write for the Migration Wizard and [code]smith), an example [wizard pull request](https://github.com/supabase/realtime/pull/1569), [run history](https://docs.blacksmith.sh/blacksmith-observability/history), [logs](https://docs.blacksmith.sh/blacksmith-observability/logs), [CI analytics](https://docs.blacksmith.sh/blacksmith-observability/dashboard), [test analytics](https://docs.blacksmith.sh/blacksmith-observability/test-analytics), [SSH access](https://docs.blacksmith.sh/blacksmith-observability/ssh-access), [monitors](https://docs.blacksmith.sh/blacksmith-observability/monitors), [[code]smith](https://docs.blacksmith.sh/codesmith/why) and its [integrations](https://docs.blacksmith.sh/codesmith/integrations), [Testbox](https://docs.blacksmith.sh/blacksmith-testbox/overview), [CLI](https://docs.blacksmith.sh/blacksmith-cli/overview), [Proof](https://docs.blacksmith.sh/proof/overview), [Series B post](https://www.blacksmith.sh/blog/announcing-blacksmiths-series-b-led-by-peak-xv-partners). The wizard's own screens were not seen; that it lets a person select workflows is inferred from the PR text.
- Effect: [4.0.0 release](https://github.com/Effect-TS/effect/releases/tag/effect%404.0.0), [migration guide](https://raw.githubusercontent.com/Effect-TS/effect/main/MIGRATION.md) (stability tiers, `effect/unstable/*` paths dropped), [repository README](https://github.com/Effect-TS/effect), npm registry entries for [`effect`](https://registry.npmjs.org/effect), [`@effect/ai-openrouter`](https://registry.npmjs.org/@effect/ai-openrouter), [`@effect/ai-openai`](https://registry.npmjs.org/@effect/ai-openai/latest), [`@effect/ai-anthropic`](https://registry.npmjs.org/@effect/ai-anthropic/latest). The 4.0.0 release year is inferred from the page.
- TanStack Start: [1.0 announcement](https://tanstack.com/blog/tanstack-start-1-0), [selective SSR](https://tanstack.com/start/latest/docs/framework/react/guide/selective-ssr), [server functions](https://tanstack.com/start/latest/docs/framework/react/guide/server-functions), [streaming from server functions](https://tanstack.com/start/latest/docs/framework/react/guide/streaming-data-from-server-functions), [execution model](https://tanstack.com/start/latest/docs/framework/react/guide/execution-model), [hosting](https://tanstack.com/start/latest/docs/framework/react/guide/hosting), [search params](https://tanstack.com/router/latest/docs/framework/react/guide/search-params), [SSR](https://tanstack.com/router/latest/docs/framework/react/guide/ssr). The server-function validator method name (`.validator` in the current docs) is to be checked against the pinned version.
- OpenRouter and alternatives: [quickstart](https://openrouter.ai/docs/quickstart), [FAQ](https://openrouter.ai/docs/faq), [pricing](https://openrouter.ai/pricing), [zero data retention](https://openrouter.ai/docs/features/zdr), [provider routing](https://openrouter.ai/docs/features/provider-routing), [Ollama OpenAI compatibility](https://docs.ollama.com/api/openai-compatibility), [vLLM OpenAI-compatible server](https://docs.vllm.ai/en/latest/serving/online_serving/openai_compatible_server/), [LiteLLM proxy](https://docs.litellm.ai/docs/simple_proxy).
