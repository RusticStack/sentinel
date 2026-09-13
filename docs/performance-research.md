# Performance research and Sentinel engineering strategy

Reviewed 2026-09-13. This is a source-backed design investigation, not a benchmark of an implemented Sentinel. Vendor numbers are attributed claims; GitHub timings below are observed API metadata, not CPU profiles. Sentinel is a **purpose-built, performance-first CI engine**, implemented from scratch in Rust. Supporting different toolchains does not mean building a general automation platform.

## Executive conclusion

The strongest recurring technique is **avoid doing and moving the same work again**: keep source objects, extracted images, dependencies, and compiler state near compute; start with cheap isolated writable views; schedule according to data locality and capacity; eliminate false dependencies; retain enough timing evidence to identify the next bottleneck.

Blacksmith is not fast simply because of its runner code. It combines fast hardware with storage and workflow optimizations. Depot independently demonstrates storage locality, persistent build state, and sharply reduced VM boot overhead. Bazel demonstrates a further class of improvement: avoiding whole build actions when all inputs are known and unchanged.

Sentinel's opportunity on the **same hardware** is a shorter data path and fewer repeated operations: direct local snapshots rather than network archive restore, retained compiler state rather than repeated compilation, persistent worker sessions, resource-aware DAG execution, and a CI-specific diagnostic/storage path. Rewriting orchestration in Rust alone cannot remove minutes spent inside a test command.

## 1. What Blacksmith actually does

### Colocated object cache — avoid the long network path

Blacksmith's July 2025 [cache engineering article][B1] describes high-single-core bare-metal CPUs/NVMe, ephemeral Firecracker VMs, a compatible Actions cache service, and colocated MinIO. Their VM/host proxies translate GitHub's Twirp/Azure-facing requests to their storage. They discovered that the Actions toolkit skipped concurrency optimizations for non-Azure-looking URLs, then restored those optimized paths through translation. Streaming buffers and pooled connections avoid unnecessary memory copies and repeated connections.

The article reports up to 10x cache improvements for some customers; its example is approximately 119 MB at 49.8 versus 327.5 MB/s. That is a cache-transfer measurement, not a 10x complete-test-suite result. Sentinel needs neither Azure emulation nor transparent Actions interception because its pipeline and protocol are owned end to end.

**Apply:** streaming transfers, connection reuse, bounded parallelism, locality, and a cache-restore deadline. Blacksmith explicitly notes that rebuilding can be faster than waiting for a degraded cache. Keep source/required artifacts distinct: only disposable caches may fall back to a miss.

### Sticky disks — remove archive transfer/materialization

[Sticky disk documentation][B2] describes ext4 disks backed by Ceph on NVMe, storage agents, cloning the last committed snapshot, mounting into a job, and committing afterward. Each job gets an isolated clone, not a common writable live disk. Their illustrative 6 GB table compares approximately 66 seconds for Actions cache, 15 seconds for Blacksmith object cache, and 3 seconds to access a sticky disk.

These are different operations: transfer throughput versus making a snapshot accessible. First-touch reads, working-set size, dirty data, snapshot commit, and remote storage cost still matter. Sentinel must measure those rather than declaring a mount to be the whole restore.

**Apply:** local immutable snapshots/job-private writable clones and trust-scoped publication. Do not copy Ceph/MinIO into a small self-hosted deployment just to copy their topology. A local filesystem fast path can be shorter, but superiority requires measurements, especially on plain filesystems without cheap snapshots.

### Two different container caches

[Docker build caching][B3] persists builder state: layers **and cache mounts**. Exporting a layer cache does not, by itself, preserve mutable `RUN --mount=type=cache` directories. Incremental compiler/package caches still help when a changed layer must execute. Blacksmith reports customer build improvements of 2–40x; this is workload-dependent reuse, not guaranteed compute acceleration.

Their docs also prescribe manifest-first Dockerfile ordering, separate unrelated builder caches to avoid churn, direct push rather than load-then-push, and native architecture workers rather than emulation. Concurrent builder snapshots currently have last-write-wins publication: correctness through isolated views does not automatically preserve every writer's newly cached work.

[Container initialization caching][B4] is separate: cache the already-extracted daemon image store, grouped by organization/region/architecture, so repeated pull and unpack are avoided. The docs describe per-job CoW views and image updates merged afterward. A warm BuildKit cache is not proof that the runtime image store is warm, or vice versa.

**Apply:** model runtime image reuse, compiler state, and optional builder state separately. Use runtime-supported immutable content rather than hand-merging live Docker databases. Builder integration is optional tooling/capability work, not a reason to require Docker in every Sentinel deployment.

### Git mirrors — fetch deltas rather than reclone

[Checkout caching][B5] uses a persistent bare mirror, incremental fetch, Git alternates for object reuse, and a self-contained checkout option when a child container cannot access the mirror. It falls back to ordinary checkout if hydration/cache is unavailable.

**Apply:** source mirror snapshots/leases, exact-SHA validation, bounded fetch concurrency, and GC that honors all active readers. Read-only shared objects do not imply a shared writable worktree. Worktree population still depends on file count and changed content; avoid extrapolating “sub-second” to every large checkout.

### Hardware and isolation

Blacksmith's hardware advantage is real in its product positioning, but unavailable as an explanation for Sentinel winning on the **same** CPU/RAM/disk allocation. Firecracker and CoW root images let it provide isolation without booting an entire cloud instance for each job. Do not compare weak isolation on one system with strong isolation on another and attribute the difference only to efficiency.

## 2. What comparable systems add

### Depot: persistent build state, cache locks, and shorter VM initialization

Depot's [cache-mount article][D1] distinguishes layer reuse from incremental state reuse. Its examples show how a small manifest change invalidates a layer yet can still reuse package-manager downloads through a cache mount. It also documents a counterexample: a globally locked cache can serialize otherwise independent builds. Cache state should be scoped per compatible workload; a cache hit that waits on a lock can be slower than a miss.

The May 2026 [microVM boot article][D2] reports an initial 7–9 second baseline reduced to roughly p50 0.6 seconds / p90 1.2 seconds on its specified hardware, using Cloud Hypervisor, direct minimal-kernel boot, removal of unnecessary services/cloud-init, a specialized init/guest agent, parallel initialization, and memory tuning. Readiness is execution of `/usr/bin/date`, with networking ready; it is **not a complete checkout/build-ready metric**. They explicitly describe just-in-time VMs without a warm standby pool in that article.

**Apply if VM execution is later justified:** specialize the measured boot critical path instead of blindly adding a warm pool. A standby pool spends idle resources; our initial rootless-container path need not acquire VM provisioning complexity to pursue low startup overhead.

The July 2026 [Depot Metal article][D3] describes bare-metal compute, dedicated NVMe-backed storage servers over NVMe-oF/TCP, host-memory caching, and S3 durability for block snapshots. It reports 30% faster workloads. The article says this rollout covers Depot CI/Sandboxes, with Actions runners/container builds still to migrate at publication. Do not conflate their different products or architecture generations.

**Apply:** keep orchestration/logging overhead outside the job's resource allocation, use local working sets, avoid repeated storage traversal. Dedicated distributed block storage is an answer to their scale, not a minimum Sentinel dependency. Kernel page cache is already a memory tier; a custom RAM cache needs evidence of benefit and bounded memory ownership.

### Bazel: dependency-aware action reuse

[Bazel remote caching][C1] describes an action cache plus a content-addressable output store. Actions include input digests, command, environment, and declared outputs. The speedup comes from not re-executing an unchanged action, not merely downloading dependencies faster.

**Apply:** let existing build tools keep their own dependency/action semantics; Sentinel supplies persistent state, scheduling, and evidence. A future Sentinel task-result cache must require declared complete inputs and conservative eligibility. Arbitrary shell code can read undeclared files, time, network services, secrets, or external state; a command string plus Git SHA is insufficient. Do not build a new Bazel or infer a sound dependency graph from changed filenames alone.

### Go: compiler cache versus test-result cache

Go's documented/tested [cache semantics][C2] distinguish build reuse from test-result reuse. `-count=1` forces fresh test execution but does not require discarding compiler cache. `GODEBUG=gocachehash=1` / `gocachetest=1` can help diagnose misses in controlled profiling runs; verbose debug output should not become default agent output.

**Apply:** persist the compiler cache across PR revisions with stable toolchain/architecture/flags context. Keep normal/race/coverage/experiment compatibility correct. Continue fresh tests where required. A complete source hash in the outer *compiler-cache namespace* destroys reuse unnecessarily; individual compiler cache entries already encode source dependencies.

## 3. Real Lockwell timing evidence

Source: [successful PR CI run 34757783544][L1], source SHA `0c87e0181c794fe2bbfeb15dc34e7b6aae375d8b`, inspected through GitHub run/jobs APIs. Run created `2026-09-13T12:41:34Z`, last job completed `12:50:11Z`, run updated `12:50:12Z`: about **8m38s**. This run is newer than the main-branch workflow inventory in the migration document. The runner names indicate org/VPS workers; physical topology, CPU quotas, disk behavior, and cache-hit state are not available in this metadata.

| Observation | Elapsed | Implication / next measurement |
|---|---:|---|
| Run creation -> initial jobs start | 2 s | This example is not a multi-minute dispatch stall |
| `test-race` / actual test command | 303 s | Separate compilation, package execution, fixed waits, CPU throttling, contention |
| `test` / unit command | 75 s | Package timing and compile-cache miss investigation |
| `test` / legacy JSON command | 71 s | Separate compatible compiler state; consider independent DAG branch within same total capacity |
| `test` / vet | 6 s | Avoid treating every step as a minutes-long bottleneck |
| `docs` / Setup Node | 26 s | Preprovisioned toolchain can remove this overhead |
| `docs` / npm install + actual lint | 3 + 6 s | Distinguish setup from useful work |
| Downstream jobs start | 12:44:33Z | Most wait behind `test`, which finishes at 12:44:31Z |
| `integration` / normal then race | 207 + 118 s | Dominant critical path; not explained by checkout alone |
| `docker` / Buildx setup + image build | 13 + 4 s | Image build itself is already short in this sample |
| `docker` / Compose test | 231 s | Inspect internal build/start/health waits and cleanup separately |
| `coverage` / broad report then floor gate | 87 + 71 s | Investigate duplicate work while preserving distinct coverage contract |
| `fuzz` / two commands | 36 + 48 s | Each includes a declared 30-second fuzz budget plus other work |
| `supply-chain` / gate | 76 s | Split tool execution, database/network work, generation |
| `playwright` / browser setup | 15 s | Warm matching browser version/dependencies |
| `playwright` / two binary builds | 9 + 14 s | Reuse compatible exact-input build artifacts |

A second recent successful PR run (`34756646843`) spans approximately 12m08s by created/updated timestamps; several others span 8–9 minutes. This is evidence that the complaint is material, not a controlled performance distribution. Do not infer p95 or claim a specific cache/CPU cause from one job summary.

Removing `needs: test` alone could overlap some work but cannot make a 303-second command finish in 45 seconds. More parallel jobs on the same saturated machine can make it worse. The next actionable evidence is per-package/test wall time, process CPU time, compiler execution, allocation/GC, I/O wait, cgroup throttling, and host-level placement across all concurrent runners.

## 4. Engineering the five-minute -> sub-minute target

**Target:** representative warm PR required-check completion p95 < 60 seconds using the same hardware and total allocated CPU/RAM/disk, the same declared assertions/coverage, and the same cache/result-freshness policy. Report first useful failure and long acceptance/audit completion separately. Do not rename partial feedback “all checks passed.”

Approximate model:

```text
feedback = delivery + admission + queue
         + longest resource-constrained path(checkout, setup, build, tests, required outputs)
         + required result publication
```

Tasks overlap only when both dependencies and resource capacity permit. Lower bounds include sequential dependencies, total CPU work / available cores, required disk bytes / effective throughput, fixed-duration tests, and external responses. Amdahl's law matters: if 60% of a run is immutable serial work, eliminating all other cost gives only 1.67x; 5x requires changing at least 80% of the elapsed critical path. Repository test-harness optimization can remove avoidable waiting without reducing assertions, but this must be measured separately from Sentinel overhead improvements.

### Provisional 55-second budget

These are an engineering allocation, not independently measured percentiles to add together:

| Portion on the critical path | Budget |
|---|---:|
| Intake/admission/dispatch after webhook receipt | 1 s |
| Warm source/environment/cache preparation | 3 s |
| Incremental build + required checks | 45 s |
| Required small evidence + result publication | 3 s |
| Margin | 3 s |

Track GitHub delivery/Checks propagation separately, while still measuring user-visible push-to-check latency. Cold runs and saturated queues have separate distributions. A cache hit must not depend on extra invisible hardware absent from the baseline.

### Sequence of experiments

1. **Baseline the work:** export run/step and Go test JSON timelines; profile isolated versus concurrent runs with identical quotas; record disk/cache/image/tool versions and host topology. Time commands outside both CI engines using identical isolation.
2. **Remove repeated preparation:** immutable prebuilt environments, warm extracted images, local Git objects, stable paths, local dependency/compiler snapshots. Compare bytes copied, page faults, and total first-user-command time.
3. **Fix invalidation:** demonstrate a cache remains useful after a small source edit or one dependency addition; toolchain/ABI/experiment changes invalidate only the incompatible layer. Audit miss reasons instead of adding larger indiscriminate cache archives.
4. **Reduce critical-path work:** remove false DAG edges; build compatible outputs once; run independent normal/race/experiment checks under a shared core budget; use balanced explicit package shards only when fixture/global-resource boundaries permit.
5. **Fix test-harness overhead in the repository:** replace unconditional sleeps with readiness/events, isolate mutable fixtures and ports, avoid repeated setup per case where equivalent, eliminate duplicated work while retaining assertions. Measure long-tail tests and verify equivalence. Sentinel exposes these costs; it does not silently rewrite commands.
6. **Consider result reuse separately:** explicit deterministic-task opt-in and producing evidence; changed-input/fresh-execution comparisons must remain separate. Lockwell defaults to `-count=1`; no hidden skipped tests to hit the target.
7. **Gate optimizations:** compare warm/cold/small-edit and concurrent workloads; require correctness under corrupt cache, concurrent writer, canceled job, worker loss, and role/trust changes. Publish misses and regressions too.

Two serial 30-second fuzz budgets already exceed a sub-minute end-to-end run after overhead. They may run concurrently if the existing hardware budget can support them with equivalent test policy, or stay visibly in a separate full-check lane only with an explicit repository policy change. The same principle applies to long chaos/durability waits. Do not silently shorten fuzz time or drop a required lane.

## Sentinel cache design

### Layers with different validity rules

| Layer | Reuse / compatibility |
|---|---|
| Environment/runtime image | Immutable digest + platform; pre-pull/unpack; retain required private-image authorization |
| Git objects | Repo/tenant/trust scoped mirror, exact SHA, reader leases; new private worktree |
| Download cache | Tool-verified package blobs; namespace tool/protocol/tenant; survives compatible lockfile edits |
| Materialized dependencies | Exact manifests/lockfiles, installer version/flags, ABI/platform, installation scripts and relevant environment |
| Compiler intermediates | Stable toolchain/platform/flags namespace; compiler owns input-level invalidation; retain across source edits |
| Builder state | Optional runtime/tool-managed layer and mutable cache-mount state; quiesced snapshots; no live DB directory merging |
| Exact task outputs/results | Opt-in complete declared input/config/environment/tool identity plus authorized producing run; side-effecting/nonhermetic tasks excluded |

Cookbooks for Go, Rust, JS (npm/pnpm/Bun), Python, and Java (Maven/Gradle) demonstrate paths and compatibility dimensions. They are editable versioned recipes, not automatic language detection that changes execution semantics. Unknown tools use the same cache-path/output contracts. Tool-native remote-cache protocols can be optional adapters after measured need; a generic directory cache does not pretend to implement every remote build protocol.

### Hot path

- Worker advertises local cache/image availability summaries, capacity, and measured disk pressure. Scheduler minimizes expected **completion time**, not only cache hit rate. Bound locality wait; prioritize already-ready required checks.
- Job gets its own writable view of immutable compatible state, preferably cheap filesystem snapshot/reflink. Portable copy fallback remains honest about cost. Reflinking a million files still incurs metadata work; benchmark whole-tree snapshots versus per-file clones.
- Bounded prefetch/single-flight immutable downloads prevent cache stampedes; one unavailable fetch must not serialize the fleet indefinitely. Never share arbitrary writable compiler/build databases across independent jobs.
- Preserve distinct generations from concurrent writers; select/promote explicitly. Merge only formats with a verified tool-supported merge operation or immutable content manifests. Expose lost reuse opportunities rather than risk corrupt shared state.
- Trusted base caches can feed private PR-local generations; PR updates cannot poison protected builds. Namespace all state by tenant/access/trust and relevant toolchain dimensions. Within-tenant sharing of private images/dependencies still requires project authorization.
- Working set stays local. Remote hydration is bounded, streaming, checksummed, resumable; compare expected restore cost with rebuild. Compression helps network bytes but can waste CPU on local data or already-compressed blobs.
- Required outputs/results become durable before final success; optional cache replication/GC continues in bounded background work. Slow cache upload must not extend PR result latency or consume unbounded disk.
- Protect active cache/object readers during GC; measure hit usefulness, dirty bytes, copy amplification, restore/first-touch/commit time, lock wait, avoided downloads, and time saved. Hit percentage alone is not a success metric.

### Result reuse boundary

Do not cache arbitrary shell success by default. A future cacheable task declares inputs including files/symlinks/modes, command/shell/workdir, tool/image/platform, relevant non-secret environment, dependency output digests, and policy version. Require constrained file/network access for a defensible completeness claim. Secret-consuming/publishing/live-system/time/randomness-sensitive tasks are ineligible by default. Secret version IDs may invalidate dependent preparation but raw secret values are never public cache-key material.

Report `reused` versus `executed`, producing run, inputs, freshness, and policy. Force-fresh rerun is explicit. Changed/unknown inputs mean execute. Native compiler reuse is valuable even when every test must run fresh.

## 5. Implementation priorities and rejection criteria

**First:** durable event-driven fleet, exact-input manifests, immutable local cache views, warm images/source/toolchains, bounded I/O, compiler-cache persistence, resource-constrained DAG timing, human/agent diagnostics. Rust ownership and bounded channels support predictable resource usage; use profiling to select copy/allocation/serialization improvements.

**Next when measured:** locality scoring refinements, filesystem snapshot backend, report-based shard suggestions, opt-in action reuse, remote cache adapters, source working-tree materialization improvements.

**Not prerequisites:** Ceph/MinIO, distributed block device, custom database, a new compiler/build system, mandatory VM pool, Actions protocol emulation, Lockwell-specific executors, or replacing all existing project tools. Optional microVM/optimized kernel/io_uring/custom allocator work earns its place by improving measured bottlenecks while preserving portability and operation cost.

Competitive validation: same hardware and total resources, equivalent isolation/check scope, separate cold/warm/result-reuse tests, at least 30 repeats for an initial pilot and a larger sample before confident tail claims. Report p50/p95/p99 with sample count/variance, maximum delay, failures, CPU-seconds, disk/network bytes, RSS, and cache state. Hosted Blacksmith/Depot comparisons disclose hardware/service differences; self-hosted equal-hardware baselines test Sentinel's architecture directly. Do not multiply “10x cache” by “40x Docker” to invent a total speedup.

Success means reaching the under-one-minute required-feedback target on a published representative workload, then expanding the workload set. If it is not met, publish the remaining critical-path cost rather than changing the benchmark scope invisibly.

## Sources

Research used first-party technical material and Context7 for build-tool semantics. Search snippets were used for discovery; findings above rely on fetched pages/documentation. Live material can change; implementation should pin dependencies and verify current behavior.

[B1]: https://www.blacksmith.sh/blog/cache
[B2]: https://docs.blacksmith.sh/blacksmith-caching/dependencies-sticky-disks
[B3]: https://docs.blacksmith.sh/blacksmith-caching/docker-builds
[B4]: https://docs.blacksmith.sh/blacksmith-caching/docker-container-caching
[B5]: https://docs.blacksmith.sh/blacksmith-caching/git-checkout-caching
[D1]: https://depot.dev/blog/how-to-use-cache-mount-to-speed-up-docker-builds
[D2]: https://depot.dev/blog/optimizing-microvm-boot-times
[D3]: https://depot.dev/blog/announcing-depot-metal
[C1]: https://bazel.build/remote/caching
[C2]: https://pkg.go.dev/cmd/go#hdr-Test_packages
[L1]: https://github.com/RusticStack/lockwell/actions/runs/34757783544
