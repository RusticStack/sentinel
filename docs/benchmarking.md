# Benchmarking

`sentinel-bench` is a Linux-first benchmark runner in [`crates/sentinel-bench`](../crates/sentinel-bench). It runs one fixed workload repeatedly, measures each run with the monotonic clock, and writes **one JSON line per benchmark run**. It is a development tool, not part of the server/worker binaries.

## Workloads and runtimes

| Workload | Command | Purpose |
|---|---|---|
| `noop` | `true` (`cmd /c exit 0` on Windows) | Reproducible floor: process spawn, container start and teardown with no user work |
| `nonzero-exit` | `sh -c 'exit 3'` | Verifies the runner refuses to record a failed workload |

| Runtime | Measured process | Notes |
|---|---|---|
| `direct` | The workload itself | Host process-spawn floor |
| `podman` | `podman run --rm [--cpus N] [--memory M] <image> <workload>` | Rootless container floor; resource usage is that of the **podman client process**, not the container |

Run from the repository root with the release profile:

```sh
cargo bench-noop --runtime direct --warm-state warm --label <host-id>
cargo bench-noop --runtime podman --image docker.io/library/busybox@sha256:<digest> --warm-state warm --label <host-id> --output bench.jsonl
```

`--warm-state` is required and operator-declared; the runner cannot detect cache state and records how much it could establish (`warm_state_basis`, below). `--warmup` runs are executed but not recorded (default 2); `--samples` defaults to 20. Any non-zero or signalled exit aborts the run with exit status 1 and writes nothing. Always reference images by digest so the record is reproducible.

## Record format (`sentinel-bench/1`)

Top-level fields: `schema`, `bench_version`, `started_at_unix_ms` (wall-clock provenance only), `label`, `workload`, `runtime`, `warm_state`, `argv`, `limits {cpus, memory}`, `source {git_commit, git_dirty}`, `tools {rustc, podman}`, `host`, `image {reference, digest, id}`, `warm_state_basis`, `interleave {runtimes, order, conditions}` (only for a group), `conditions`, `warmup`, `samples[]`, `summary`.

`host` records hostname, OS, kernel, CPU model, online CPUs, total memory, working directory and its filesystem/mount point, cgroup v2 controllers and user. `source` is always recorded: the runner asks `git -C <the checkout it was built from>` for `HEAD` and the dirty state, so it names its source even when started from another directory, and it refuses to measure or write anything when the commit cannot be read (for example a checkout owned by another user without `safe.directory`). `tools.rustc` is the compiler that built the runner, captured at build time (Cargo rebuilds the runner when the toolchain changes), so it does not depend on `rustc` being on the runner user's `PATH`; `tools.podman` is read from `PATH` at run time for the Podman runtime. An absent value means the tool was unavailable, never a default.

Each sample has `index`, `elapsed_ns` (monotonic, spawn to reaped), `exit_code`, and on Unix the `wait4` usage of the direct child: `user_cpu_ns`, `system_cpu_ns`, `max_rss_kib`, `block_in`, `block_out`. Unmeasured fields are omitted. `summary` holds `count`, `min_ns`, `median_ns`, `p95_ns` (nearest-rank), `max_ns` and the spread: `mean_ns`, `stddev_ns` (sample, n - 1; absent for one sample) and `mad_ns` (median absolute deviation from the median, which one slow outlier cannot move). With fewer than 20 samples the nearest-rank p95 is the largest sample, so `summary` carries `"p95_is_max": true` and the p95 describes one run, not a tail; report such a record's median and spread, not its p95. Samples are sequential, single-observer measurements; do not add them to any other phase.

**Conditions.** `conditions` is read from the kernel around the measured window (before the first warm-up run and after the last sample): CPU pressure (`some`, avg10 and avg60) at the start and at the end, hypervisor steal time over the window in nanoseconds (`/proc/stat`), and cpu0's `scaling_governor`. A field the kernel does not expose (a VM often has no cpufreq; pressure needs PSI) is absent, never zero. A contract run refuses a start at or over 5 % pressure; the end values say whether the host got busy during the run, which a start check cannot. A run whose end pressure or steal is high is not a baseline, even though it was recorded.

In an interleaved group (below) the runtimes alternate, so one window around the group would charge each of them with the others' load. Each run of the group is probed on its own instead, and a record's `conditions` cover only that runtime's runs (its warm-ups and samples): the stall and steal fields are the sum of the deltas seen while that runtime's runs executed, `*_start` is read just before its first run and `*_end` just after its last, and a counter the kernel did not expose for some run is absent from the whole sum rather than a partial total. The counters are host-wide, so they say what the host was doing during that runtime's runs, not what the runtime caused. The group names this in `interleave.conditions` (`per-runtime`); a group record without that field was taken before it existed and holds one block shared by every runtime of its group.

**Warm state.** `--warm-state` stays operator-declared, and `warm_state_basis` says how much of it the runner could establish: `contract-prepare` (a cold contract condition: the contract's own per-run preparation resets the state, which the runner executes before every run, but does not observe), `warmup-run` (declared warm, and at least one identical unmeasured run completed before the first sample), or `unverified` (everything else: a cold declaration outside a contract, or warm with `--warmup 0`). A warm Podman run whose image is not present locally is refused, since the first sample would pull. Treat `unverified` records as indicative.

**Interleaved comparison.** `--interleave <runtime>` (repeatable) measures the extra runtimes in the same invocation, alternating with `--runtime` sample by sample in ABBA order: the order reverses every sample (A B, B A, A B, ...), so drift in host load, page cache or frequency lands on every runtime alike instead of on whichever ran last. Each runtime gets its own record, all naming the group in `interleave {runtimes, order, conditions}`, and each sample carries `seq`, its position in the whole sequence (with `--runtime direct --interleave scoped`, direct holds seq 0, 3, 4, 7, ... and scoped 1, 2, 5, 6, ...). Compare the runtimes of one group, not records taken in separate invocations at different times; the F05 and B01 comparisons ran back to back as separate invocations and are not interleaved.

**Script records.** Records written by the benchmark scripts rather than the runner (`b02-sentinel.sh`, `b03-latency.py`) carry a `build {commit, dirty, binary_sha256}` and a `host` block too, taken from the checkout named by `SENTINEL_SRC` / `--source`; a script refuses to write without it. Older B02, B03 and B04 records carry neither and are not back-filled.

**Naming the build.** A caller passes the build once: `bench/run-stamped.sh CHECKOUT BINARY b03 ROOT OUT` exports `SENTINEL_SRC` (the checkout the binary was built from) and `SENTINEL_BIN` (hashed into the record) and starts the harness; `bench/stamp.sh` run directly prints the stamp object. `sentinel-bench` stamps itself from the checkout it was built in. `b02-sentinel.sh`, `b03-latency.py`, `p14-pilot.sh`, `b09-harness.py`, `k02-cache-clone.sh` and `f07-storage.sh` refuse to write without it; `c02-engines.sh`, `k07-recipes.sh`, `k09-before-after.sh` and `r06-idle.sh` stamp the same way (the K09 meta line keeps its own `host` block and gets the `build`). The GitHub-collected baselines (`b01a-github.py`, `b02-github-collect.py`) measure no Sentinel build and carry none.

**Dirty means tracked changes.** `git_dirty` / `dirty` is true only when a tracked file differs from `HEAD` (`git status --porcelain --untracked-files=no`); untracked files are ignored, because a scratch file does not change what was built. A new source file that is not yet added therefore does not make a build dirty: `git add` it, or commit, before measuring.

**Shuffle seed.** `k02-cache-clone.sh` and `f07-storage.sh` shuffle the clone-mode order per round from a recorded seed: every record carries `shuffle_seed`, and a round's order is `shuf` seeded with `<shuffle_seed>/<fs>/<round>` (`bench/stamp.sh` `shuffle_lines`), so the order can be reproduced. `SHUF_SEED=…` replays a run; otherwise a fresh seed is made and printed. `position` still records the realised order. Records taken before this carry no seed. `python3 -m unittest bench/test_bench_hygiene.py` replays a seed, checks that an untracked file leaves `dirty` false and a tracked edit sets it, and checks that the stamp text survives being spliced into a record with `sed`.

## F05 baseline: direct rootless runtime

Record: [`bench/f05-noop-baseline.jsonl`](../bench/f05-noop-baseline.jsonl), captured 2026-09-13 21:34 UTC+1.

| Item | Value |
|---|---|
| Host | `development-host`, Intel Core i7-13700KF, 24 logical CPUs, 15.5 GiB visible RAM |
| Environment | Ubuntu 24.04.4 LTS on WSL2, kernel `6.18.33.2-microsoft-standard-WSL2`, systemd PID 1 |
| Filesystem | ext4 on `/`, workdir `/home/benchmark` (native Linux disk, not `/mnt/d`) |
| Runtime | Podman 4.9.3, rootless as user `benchmark` (subuid/subgid `100000:65536`), runc, overlay, cgroup v2 via systemd, controllers `cpuset cpu io memory hugetlb pids rdma` |
| Image | `docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662` |
| Source | Commit that introduced this file (the runner ran outside the checkout, so `source.git_commit` is absent in the record) — see the correction below |

**Correction (provenance of this record).** All four records carry `"source":{"git_commit":null,"git_dirty":null}` and `"tools":{"rustc":null,…}`: that runner build read both from `PATH` in the working directory, and it ran as `benchmark` in `/home/benchmark`, outside the checkout and without `rustc`. The values are not recoverable from the record and are **not** filled in after the fact; the only attribution is the commit that added the file, which says what source was checked in at the time, not what the measured binary was built from, and whether that tree was dirty is unknown. The runner always records both (above). Also note that the "cold" row's state is operator-declared (`--warm-state cold`) and cannot be verified from the record: it is one sample, starting about 155 ms after the direct run's record started, which leaves roughly 130 ms after the direct run's own work for `podman system prune` and the pre-sample `podman image inspect` — possible, but tight. Treat the cold figure as indicative only; the warm medians and p95s recompute exactly from their samples (0.252 ms, 250.4 ms and 252.3 ms medians, nearest-rank).

| Runtime | Warm state | Limits | Samples | min | median | p95 | max | client max RSS |
|---|---|---|---|---|---|---|---|---|
| direct | warm | none | 50 | 0.21 ms | 0.25 ms | 0.32 ms | 0.40 ms | 2.5 MiB |
| podman | cold (after `podman system prune`, image present) | none | 1 | 223 ms | – | – | – | 40.7 MiB |
| podman | warm | none | 20 | 233 ms | 250 ms | 269 ms | 272 ms | 40.2 MiB |
| podman | warm | `--cpus 1 --memory 256m` | 20 | 227 ms | 252 ms | 276 ms | 281 ms | 40.8 MiB |

Interpretation, limited to what was measured:

- Container start/teardown of an already-pulled image costs about **250 ms per job** on this host, roughly a thousand times the process-spawn floor. This is the floor that every future executor measurement subtracts against; it says nothing about checkout, cache or compile phases.
- Requesting CPU/memory limits did not change the start cost measurably. Whether the limits are **enforced** is unverified here and remains an F07 probe.
- Podman writes about 512 blocks per run even for a no-op; storage/cgroup churn is a candidate for later optimization, after profiling.
- The WSL2 kernel and the `/ is not a shared mount` warning make this a **development reference, not a production qualification**. Repeat the same commands on a dedicated Linux host and append the record before treating any number as a target.

### The same baseline on the verification VPS

Record: [`bench/f05-noop-vps.jsonl`](../bench/f05-noop-vps.jsonl), captured 2026-09-28 15:13 UTC with the same four commands and image.

| Item | Value |
|---|---|
| Host | reference-host VPS (QEMU guest), AMD EPYC 9645, 12 vCPUs, 31 GiB RAM |
| Environment | Ubuntu 26.04.1 LTS, kernel `7.0.0-31-generic` |
| Filesystem | ext4 on `/`, workdir `/home/benchmark` |
| Runtime | Podman 5.7.0, rootless as `benchmark`, runc, overlay, cgroup v2, controllers `cpuset cpu io memory hugetlb pids rdma misc dmem` |
| Source | `420ce8c`, `git_dirty: true` — the uncommitted change was the four store-test fixes committed in `defeb28`; nothing the runner builds or runs |
| Load | load average 0.97 before and 1.18 after; CPU pressure (`some`, avg60) 0.43 % before, 0.70 % after. Unrelated host workloads were idle for the run |

| Runtime | Warm state | Limits | Samples | min | median | p95 | max | client max RSS |
|---|---|---|---|---|---|---|---|---|
| direct | warm | none | 20 | 0.93 ms | 1.23 ms | 1.62 ms | 1.82 ms | 2.8 MiB |
| podman | cold (after `podman system prune`, image present) | none | 1 | 445 ms | – | – | – | 45.5 MiB |
| podman | warm | none | 20 | 396 ms | 428 ms | 464 ms | 465 ms | 46.4 MiB |
| podman | warm | `--cpus 1 --memory 256m` | 20 | 373 ms | 417 ms | 437 ms | 466 ms | 46.3 MiB |

- A warm container start costs about **420 ms** here, against 250 ms on the WSL2 development machine: the production-shaped host is slower, not faster, for this floor. Process spawn is about 1.2 ms against 0.25 ms. Neither difference is explained by this record (different CPUs, a virtualized guest, and Podman 5.7 against 4.9); profile before attributing it.
- Limits again make no measurable difference to start cost.
- An earlier attempt on 2026-09-27 started as the other CI burst (CPU pressure 68 %, load 14; warm median 1.36 s) and was discarded, not recorded: a contended host is not a baseline.

## K09 before/after: the cache path's own cost

Record: [`bench/k09-before-after.jsonl`](../bench/k09-before-after.jsonl) (first line carries host/kernel/filesystem provenance), driven by [`bench/k09-before-after.sh`](../bench/k09-before-after.sh). Every number is a real attempt through the worker's own path — fresh workspace, pinned local checkout, digest-pinned image, cache restore, rootless Podman steps, publication — not the `bench-noop` process-spawn floor.

| Item | Value |
|---|---|
| Host | `development-host`, Intel Core i7-13700KF, 24 logical CPUs |
| Environment | Ubuntu 24.04.4 LTS on WSL2, kernel `6.18.33.2-microsoft-standard-WSL2` |
| Filesystem | ext4 workdir `/srv/k09` (native Linux disk, not `/mnt/d`) |
| Runtime | Podman 4.9.3, rootless as `benchmark` |
| Image | `docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662` |

**No-op job** — one `true` step; `bare` has no `cache:` block, `cache-cold` is the first run on an empty store (`absent → sealed`), `cache-warm` the steady state (`hit → unchanged`), two declared entries: a workspace path and an absolute mount path.

| Case | n | checkout | steps | finalize | total median | total p95 |
|---|---|---|---|---|---|---|
| noop-bare | 7 | 83.0 ms | 121.1 ms | 261.8 ms | 465.7 ms | 488.1 ms |
| noop-cache-cold | 1 | 82.5 ms | 100.7 ms | 298.3 ms | 481.5 ms | – |
| noop-cache-warm | 7 | 82.8 ms | 121.3 ms | 265.8 ms | 470.9 ms | 503.8 ms |

The warm cache path is small next to the bare job: the restore (lookup + lock + clone, 5.3 ms median, measured during preparation and so outside `total`) plus the `unchanged` commit-skip (2.7 ms inside `finalize`) for two entries — about 10.5 ms end to end, see the correction below (per-entry `lookup_ns`/`clone_ns`/`commit_ns` are on each record). The cold seal of the same two tiny entries costs ≈20–40 ms once.

**Incremental build** — the custom-tool recipe's `deps`/`build`/`test` steps on a fresh small source edit each sample: `nocache` runs the same steps with no `cache:` block (stores move under the workspace), `cold` wipes the store every run (`absent → sealed` ×3 entries), `warm` is primed at the base commit then runs sequential edits, numbered from 2 because the base tree's `lib.c` already returns 1 (numbering from 1 would make the first edit commit a no-op and the sample would measure nothing) — `deps.txt` never changes, so all three keys hit; the compile step prints `reused main.c` / `built lib.c` every run, and `cc` seals a new accumulating generation (`reused_bytes` grows across the samples).

| Case | n | checkout | steps | finalize | total median | total p95 |
|---|---|---|---|---|---|---|
| incremental-nocache | 7 | 82.6 ms | 423.1 ms | 282.4 ms | 788.3 ms | 822.5 ms |
| incremental-cold | 7 | 82.5 ms | 442.6 ms | 312.3 ms | 854.6 ms | 905.9 ms |
| incremental-warm | 7 | 82.5 ms | 422.3 ms | 274.2 ms | 778.8 ms | 833.0 ms |

Interpretation, limited to what was measured:

- On this fixture the warm-vs-nocache wall-clock delta is inside noise — the per-input build is a `cp`, so reuse saves ~1 ms. What the records do prove is the *mechanism*: every warm run hits all three entries, rebuilds exactly the changed input, and re-seals the compiler namespace. For a real wall-clock delta the K07 record on the same host is the honest citation: `rust` cold 843.7 ms steps vs warm 321.5 ms vs small-edit 441.8 ms ([`bench/k07-recipes.jsonl`](../bench/k07-recipes.jsonl)).
- The cold cache path is *slower* than no cache by ≈66 ms median — the cost of sealing three generations inside `finalize`. That is the honest price of publication on a job that does real work; it is paid once per generation, not per file restored.
- Same caveat as the F05 baseline: a WSL2 development host, reference numbers only.

**Correction.** The committed record is unchanged; what the tables above claim about it is corrected here, recomputed from `bench/k09-before-after.jsonl`:

- The `total` column is `checkout_ns + steps_ns + finalize_ns`. It leaves out preparation after the checkout — `image_pull_ns`, `container_start_ns` (≈200 ms median) — and with it the **cache restore**, which runs in preparation, not in `finalize`. Including checkout, image pull, container start, steps and finalize, the medians are noop-bare 728.1 ms, noop-cache-warm 732.8 ms, incremental-nocache 1032.1 ms, incremental-warm 1039.8 ms.
- The warm path's cost is therefore not "≈5 ms inside `finalize`": the restore (per-entry `lookup_ns + lock_wait_ns + clone_ns`, summed over the two entries) is 5.34 ms median for noop-cache-warm and 7.52 ms for incremental-warm, *outside* `total`; the `unchanged` commit-skip is 2.65 ms median inside `finalize`. The honest warm-vs-bare delta of the no-op job is about 10.5 ms (5.2 ms in `total` plus the 5.3 ms restore) — still small, and still inside the run-to-run noise of the container start.
- The p95 column is an interpolated percentile; nearest-rank over the same seven samples gives noop-bare 488.5, noop-cache-warm 508.4, incremental-nocache 828.0, incremental-cold 917.4, incremental-warm 838.9 ms.
- The record holds 38 lines: one `meta` line and 37 attempts, one of which is the single `incremental-prime` run that seeds the warm case — 36 measured case samples plus the prime.

## B01: contracts and identical isolation

Part 14 measures representative checks under frozen contracts. The runner's `--contract`, `--lane`, `--condition` and `--root` options measure a contract lane only when the host and inputs match the contract, and its `scoped` runtime gives a direct process the same CPU and memory caps a container gets. See [benchmark contracts](benchmark-contracts.md) for the contract, the conditions, the identical-isolation comparison and its results.

**Stamp test and exceptions.** `bench/test_bench_hygiene.py` scans every `bench/*.jsonl`: each record must carry `build.commit` (not null) and a `host.hostname` that is an anonymized label (lower-case letters, digits and hyphens, no address). The files that predate the stamp are listed in the test as `LEGACY_UNSTAMPED`, each with its reason: the GitHub-collected and Woodpecker baselines and the legacy Go CI runs measured no Sentinel build, the dry-run files of the paired B11 harness have none, and the older B01, B02, B03, B04, C02, F05, F07, K02, K07, K09, M02, Q09, R04, R06 and U01 records were taken before the stamp and are not back-filled, because a commit written after the fact would be invented. The set is exact: a new file without a stamp fails, and a legacy file that becomes fully stamped must leave the list. No committed record has a null commit; a null commit is not an accepted exception. The same test lists the writers that stamp and checks that each still does.

**Benchmark lock.** A script that runs a command under the benchmark lock uses `flock -x -o LOCK command` (`-o` closes the lock descriptor in the child), so a process the command starts and leaves behind cannot keep the lock after the script returns. The test fails any `flock` on a command in `bench/*.sh` or `bench/*.py` without `-o`; descriptor-form locks the shell owns (`flock 9`) and `b09-harness.py`'s own install lock are not command locks.

## Log-ack batching

The controller acknowledges log frames per burst: each frame is written with `LogStore::append_deferred`, then one `LogStore::sync` (an `fdatasync` of the segment) precedes one `LogAck` ([logs](logs.md)). `crates/sentinel-store/examples/log-ack-bench.rs` measures what that saves, through the real `LogStore` on the file system named by `--dir`: for each burst size (default 1, 8, 64, 256 frames) it stores `--frames` frames (default 4096) of `--frame-bytes` bytes (default 256) into a fresh store, `--rounds` times (default 5), reversing the order of the burst sizes every round. A burst of 1 is an acknowledgement, and so a sync, per frame. Run it through `bench/log-ack.sh`, which adds the `build` and `host` stamp (`SENTINEL_SRC`, `SENTINEL_BIN`, the example binary built from that checkout) and appends the line to `bench/log-ack.jsonl`.

Record `sentinel-bench/log-ack/1`: `frames`, `frame_bytes`, `rounds`, `order` (the burst sizes in the order each round ran them) and `results[]`, one entry per burst size with `burst_frames`, `syncs_per_run`, `elapsed_ns` (one per round, monotonic), `median_elapsed_ns`, `min_elapsed_ns`, `max_elapsed_ns`, `median_ns_per_frame`, `frames_per_s_median` and `sync_ns {count, median, p95, p95_is_max, max}` over every sync of every round (`p95_is_max` is true when fewer than 20 syncs were pooled; the per-round `elapsed_ns` carries no percentile). The spread of the per-run figures is in `elapsed_ns`; the sync percentiles pool every sync call of every round. A record is a baseline only from a quiet host with the stamp's host block naming the filesystem under `--dir` (a smoke run on a shared host proves the harness, not the saving). **No record is committed yet**: the figure `docs/logs.md` calls unmeasured stays unmeasured until `bench/log-ack.jsonl` exists.

## Checks lane delivery latency

`crates/sentinel-checks/examples/checks-lane-bench.rs` measures how long a run's checks wait between being enqueued and reaching GitHub. It builds a real `Store` on the file system named by `--dir`, starts the real `Lane` with the real `GithubChecks` publisher, and points the publisher's App at a fake GitHub endpoint on loopback (installation lookup, token mint, repository lookup, check-run create and update, with the same answers `tests/delivery.rs` scripts). A sample records `burst` runs back to back (`runs::create_run`, the provenance row and `checks::record_run`, the writes a push makes) and waits for the endpoint to receive every queued check of every run (an aggregate plus one per job, so two per run). The clock starts when the write of that run begins and stops at the endpoint's receive time for the first check, and again for the last. Each (round, burst) gets a fresh store, endpoint and lane, and one unmeasured run goes first: its latency is reported as `cold_first_run_ns` (installation lookup and token mint) and not pooled with the steady state. Burst sizes default to 1 and 8, `--runs` (default 16) runs per sample, `--rounds` (default 5) rounds, the order of the burst sizes reversing every round (ABBA). `--github-ms` adds a fixed delay to every reply of the fake endpoint, `--idle-ms` overrides `Config::idle` (the lane's production default is used otherwise).

What it measures and what it does not: the Sentinel side of the path (the commit notifier waking the lane, the guarded read, signing the App JWT and minting the token once, the HTTP request, the guarded write-back), on loopback with an endpoint that answers at once. It says nothing of GitHub's own latency or rate limits, and a TLS handshake is not in it (the endpoint is plain HTTP, as in the tests). Run it through `bench/checks-lane.sh`, which adds the `build` and `host` stamp (`SENTINEL_SRC`, `SENTINEL_BIN`, the example built from that checkout) and appends the line to `bench/checks-lane.jsonl`.

Record `sentinel-bench/checks-lane/1`: `rounds`, `runs`, `checks_per_run`, `github_delay_ms`, `lane_idle_ms`, `order`, `p95_is_max` (true below 20 pooled runs) and `results[]`, one per burst size with `burst_runs`, `runs_per_round`, `cold_first_run_ns` (one per round), and `enqueue_to_first_check_ns`, `enqueue_to_all_checks_ns` and `enqueue_write_ns`, each `{count, min, median, p95, max}` over every run of every round. **No record is committed yet**: a run on the verification VPS proves the harness, and a baseline needs a quiet host.

## S3 hashing and signing

`crates/sentinel-s3/examples/s3-hash-bench.rs` times what a put costs on the CPU before a byte leaves: `client::body_hashes` (the signed SHA-256 payload hash and `Content-MD5` from one 64 KiB-chunk walk, as `put_object` and `upload_part` call it), `sigv4::sha256_hex` and `client::content_md5` alone, the two-pass alternative (`sha256_then_md5`) the one-walk design replaced, and `sigv4::authorization` (Signature V4 signing of a PutObject's headers, independent of the payload). No network, no service, no allocation of the payload inside the timed region. Payload sizes default to 4 KiB, 64 KiB, 1 MiB and 16 MiB (`--sizes`, bytes); each case repeats until it has hashed `--sample-mib` MiB (default 64, at least one call), `--rounds` rounds (default 7) with the case order reversing every round (ABBA), and signing runs `--sign-iterations` (default 20,000) calls per round. Run it through `bench/s3-hash.sh` (stamp as above, `bench/s3-hash.jsonl`).

Record `sentinel-bench/s3-hash/1`: `rounds`, `sample_mib`, `order`, `results[]` (`bytes`, `case`, `ns_per_call` one per round, `median_ns_per_call`, `min_ns_per_call`, `max_ns_per_call`, `mib_per_s_median`) and `sign {iterations_per_round, ns_per_call, median_ns_per_call, min_ns_per_call, max_ns_per_call}`. The figures are CPU and memory bandwidth of the host named in the stamp; they are not comparable across hosts. **No record is committed yet.**

## Backup rehash cost

`backup::verify` rehashes the snapshot and every object and manifest it names ([backup](backup.md#verifying)); `backup::create` does the same while it copies. `crates/sentinel-store/examples/backup-rehash-bench.rs` measures that cost at configurable object counts: for each of `--counts` (default 100 and 1000) it builds a real store with that many distinct objects of `--object-bytes` bytes (default 1 MiB), takes one backup, then times `backup::verify` over `--rounds` rounds (default 5) in an order that reverses every round (ABBA), and, in the same round, a bare BLAKE3 read of the same object files in the backup. The bare read is the floor the rehash cannot beat; the difference (`median_overhead_ns`) is the snapshot hash, SQLite's `integrity_check` and the per-row work. Every verification must pass and check exactly the expected number of objects, or the bench fails rather than report a time. Setup is not timed. The datasets exist twice on disk (objects and the backup copy) and all counts coexist, so the bench refuses a combination above `--max-gib` (default 8) before writing anything, and removes everything it created under `--dir`. Run it through `bench/backup-rehash.sh` (stamp as above, `bench/backup-rehash.jsonl`).

Record `sentinel-bench/backup-rehash/1`: `object_bytes`, `rounds`, `order`, `cache` (always `warm-unless-dataset-exceeds-memory`: the bench does not drop the page cache, so a figure for a dataset smaller than memory is a warm-read figure; the cold-disk figure needs a dataset larger than memory) and `results[]` with `objects`, `dataset_bytes`, `verify_ns` and `floor_ns` (one per round), `median_verify_ns`, `min_verify_ns`, `max_verify_ns`, `median_floor_ns`, `median_verify_ns_per_object`, `median_overhead_ns` and `verify_mib_per_s_median`. The R04 drill's one-off verify figure (`bench/r04-backup-drill.jsonl`) is a different dataset and is not a series with this. **No record is committed yet.**

## Reproducing

1. Prepare rootless Podman for a non-root user per [Development](development.md#linux-executor-work) and pull the image by digest.
2. Build with `cargo release-linux` (or `cargo build --release -p sentinel-bench`) and copy `sentinel-bench` to a native-filesystem directory owned by that user.
3. As that user, run the direct baseline, then `podman system prune -f`, one `--warm-state cold --warmup 0 --samples 1` run, then warm runs with and without limits, all with `--output` to one file.
4. Commit the record under `bench/` and summarize it here with the host identity and any caveats.
