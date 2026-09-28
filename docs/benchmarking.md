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

`--warm-state` is required and operator-declared; the runner cannot detect cache state. `--warmup` runs are executed but not recorded (default 2); `--samples` defaults to 20. Any non-zero or signalled exit aborts the run with exit status 1 and writes nothing. Always reference images by digest so the record is reproducible.

## Record format (`sentinel-bench/1`)

Top-level fields: `schema`, `bench_version`, `started_at_unix_ms` (wall-clock provenance only), `label`, `workload`, `runtime`, `warm_state`, `argv`, `limits {cpus, memory}`, `source {git_commit, git_dirty}`, `tools {rustc, podman}`, `host`, `image {reference, digest, id}`, `warmup`, `samples[]`, `summary`.

`host` records hostname, OS, kernel, CPU model, online CPUs, total memory, working directory and its filesystem/mount point, cgroup v2 controllers and user. `source` is always recorded: the runner asks `git -C <the checkout it was built from>` for `HEAD` and the dirty state, so it names its source even when started from another directory, and it refuses to measure or write anything when the commit cannot be read (for example a checkout owned by another user without `safe.directory`). `tools.rustc` is the compiler that built the runner, captured at build time (Cargo rebuilds the runner when the toolchain changes), so it no longer depends on `rustc` being on the runner user's `PATH`; `tools.podman` is read from `PATH` at run time for the Podman runtime. An absent value means the tool was unavailable, never a default.

Each sample has `index`, `elapsed_ns` (monotonic, spawn to reaped), `exit_code`, and on Unix the `wait4` usage of the direct child: `user_cpu_ns`, `system_cpu_ns`, `max_rss_kib`, `block_in`, `block_out`. Unmeasured fields are omitted. `summary` holds `count`, `min_ns`, `median_ns`, `p95_ns` (nearest-rank) and `max_ns`. Samples are sequential, single-observer measurements; do not add them to any other phase.

## F05 baseline: direct rootless runtime

Record: [`bench/f05-noop-baseline.jsonl`](../bench/f05-noop-baseline.jsonl), captured 2026-09-13 21:34 UTC+1.

| Item | Value |
|---|---|
| Host | `DOOMBRINGER`, Intel Core i7-13700KF, 24 logical CPUs, 15.5 GiB visible RAM |
| Environment | Ubuntu 24.04.4 LTS on WSL2, kernel `6.18.33.2-microsoft-standard-WSL2`, systemd PID 1 |
| Filesystem | ext4 on `/`, workdir `/home/sentinelbench` (native Linux disk, not `/mnt/d`) |
| Runtime | Podman 4.9.3, rootless as user `sentinelbench` (subuid/subgid `100000:65536`), runc, overlay, cgroup v2 via systemd, controllers `cpuset cpu io memory hugetlb pids rdma` |
| Image | `docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662` |
| Source | Commit that introduced this file (the runner ran outside the checkout, so `source.git_commit` is absent in the record) — see the correction below |

**Correction (provenance of this record).** All four records carry `"source":{"git_commit":null,"git_dirty":null}` and `"tools":{"rustc":null,…}`: that runner build read both from `PATH` in the working directory, and it ran as `sentinelbench` in `/home/sentinelbench`, outside the checkout and without `rustc`. The values are not recoverable from the record and are **not** filled in after the fact; the only attribution is the commit that added the file, which says what source was checked in at the time, not what the measured binary was built from, and whether that tree was dirty is unknown. The runner now always records both (above), so records appended from here on carry them. Also note that the "cold" row's state is operator-declared (`--warm-state cold`) and cannot be verified from the record: it is one sample, starting about 155 ms after the direct run's record started, which leaves roughly 130 ms after the direct run's own work for `podman system prune` and the pre-sample `podman image inspect` — possible, but tight. Treat the cold figure as indicative only; the warm medians and p95s recompute exactly from their samples (0.252 ms, 250.4 ms and 252.3 ms medians, nearest-rank).

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
| Host | netcup VPS (QEMU guest), AMD EPYC 9645, 12 vCPUs, 31 GiB RAM |
| Environment | Ubuntu 26.04.1 LTS, kernel `7.0.0-31-generic` |
| Filesystem | ext4 on `/`, workdir `/home/sentinelbench` |
| Runtime | Podman 5.7.0, rootless as `sentinelbench`, runc, overlay, cgroup v2, controllers `cpuset cpu io memory hugetlb pids rdma misc dmem` |
| Source | `420ce8c`, `git_dirty: true` — the uncommitted change was the four store-test fixes committed in `defeb28`; nothing the runner builds or runs |
| Load | load average 0.97 before and 1.18 after; CPU pressure (`some`, avg60) 0.43 % before, 0.70 % after. The host is shared with production services and another project's CI, which was idle for the run |

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
| Host | `DOOMBRINGER`, Intel Core i7-13700KF, 24 logical CPUs |
| Environment | Ubuntu 24.04.4 LTS on WSL2, kernel `6.18.33.2-microsoft-standard-WSL2` |
| Filesystem | ext4 workdir `/srv/k09` (native Linux disk, not `/mnt/d`) |
| Runtime | Podman 4.9.3, rootless as `sentinelbench` |
| Image | `docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662` |

**No-op job** — one `true` step; `bare` has no `cache:` block, `cache-cold` is the first run on an empty store (`absent → sealed`), `cache-warm` the steady state (`hit → unchanged`), two declared entries: a workspace path and an absolute mount path.

| Case | n | checkout | steps | finalize | total median | total p95 |
|---|---|---|---|---|---|---|
| noop-bare | 7 | 83.0 ms | 121.1 ms | 261.8 ms | 465.7 ms | 488.1 ms |
| noop-cache-cold | 1 | 82.5 ms | 100.7 ms | 298.3 ms | 481.5 ms | – |
| noop-cache-warm | 7 | 82.8 ms | 121.3 ms | 265.8 ms | 470.9 ms | 503.8 ms |

The warm cache path is small next to the bare job: the restore (lookup + lock + clone, 5.3 ms median, measured during preparation and so outside `total`) plus the `unchanged` commit-skip (2.7 ms inside `finalize`) for two entries — about 10.5 ms end to end, see the correction below (per-entry `lookup_ns`/`clone_ns`/`commit_ns` are on each record). The cold seal of the same two tiny entries costs ≈20–40 ms once.

**Incremental build** — the custom-tool recipe's `deps`/`build`/`test` steps on a fresh small source edit each sample: `nocache` runs the same steps with no `cache:` block (stores move under the workspace), `cold` wipes the store every run (`absent → sealed` ×3 entries), `warm` is primed at the base commit then runs sequential edits — `deps.txt` never changes, so all three keys hit; the compile step prints `reused main.c` / `built lib.c` every run, and `cc` seals a new accumulating generation (`reused_bytes` grows across the samples).

| Case | n | checkout | steps | finalize | total median | total p95 |
|---|---|---|---|---|---|---|
| incremental-nocache | 7 | 82.6 ms | 423.1 ms | 282.4 ms | 788.3 ms | 822.5 ms |
| incremental-cold | 7 | 82.5 ms | 442.6 ms | 312.3 ms | 854.6 ms | 905.9 ms |
| incremental-warm | 7 | 82.5 ms | 422.3 ms | 274.2 ms | 778.8 ms | 833.0 ms |

Interpretation, limited to what was measured:

- On this fixture the warm-vs-nocache wall-clock delta is inside noise — the per-input build is a `cp`, so reuse saves ~1 ms. What the records do prove is the *mechanism*: every warm run hits all three entries, rebuilds exactly the changed input, and re-seals the compiler namespace. For a real wall-clock delta the K07 record on the same host is the honest citation: `rust` cold 843.7 ms steps vs warm 321.5 ms vs small-edit 441.8 ms ([`bench/k07-recipes.jsonl`](../bench/k07-recipes.jsonl)).
- The cold cache path is *slower* than no cache by ≈66 ms median — the cost of sealing three generations inside `finalize`. That is the honest price of publication on a job that does real work; it is paid once per generation, not per file restored.
- Same caveat as the F05 baseline: a WSL2 development host, reference numbers only.

**Correction (cache audit, P07 K09 evidence).** The committed record is unchanged; what the tables above claim about it is corrected here, recomputed from `bench/k09-before-after.jsonl`:

- The `total` column is `checkout_ns + steps_ns + finalize_ns`. It leaves out preparation after the checkout — `image_pull_ns`, `container_start_ns` (≈200 ms median) — and with it the **cache restore**, which runs in preparation, not in `finalize`. Including checkout, image pull, container start, steps and finalize, the medians are noop-bare 728.1 ms, noop-cache-warm 732.8 ms, incremental-nocache 1032.1 ms, incremental-warm 1039.8 ms.
- The warm path's cost is therefore not "≈5 ms inside `finalize`": the restore (per-entry `lookup_ns + lock_wait_ns + clone_ns`, summed over the two entries) is 5.34 ms median for noop-cache-warm and 7.52 ms for incremental-warm, *outside* `total`; the `unchanged` commit-skip is 2.65 ms median inside `finalize`. The honest warm-vs-bare delta of the no-op job is about 10.5 ms (5.2 ms in `total` plus the 5.3 ms restore) — still small, and still inside the run-to-run noise of the container start.
- The p95 column is an interpolated percentile; nearest-rank over the same seven samples gives noop-bare 488.5, noop-cache-warm 508.4, incremental-nocache 828.0, incremental-cold 917.4, incremental-warm 838.9 ms.
- The record holds 38 lines: one `meta` line and 37 attempts, one of which is the single `incremental-prime` run that seeds the warm case — 36 measured case samples plus the prime.

## Reproducing

1. Prepare rootless Podman for a non-root user per [Development](development.md#linux-executor-work-f05f07-and-w03-onward) and pull the image by digest.
2. Build with `cargo release-linux` (or `cargo build --release -p sentinel-bench`) and copy `sentinel-bench` to a native-filesystem directory owned by that user.
3. As that user, run the direct baseline, then `podman system prune -f`, one `--warm-state cold --warmup 0 --samples 1` run, then warm runs with and without limits, all with `--output` to one file.
4. Commit the record under `bench/` and summarize it here with the host identity and any caveats.
