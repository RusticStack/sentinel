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

`host` records hostname, OS, kernel, CPU model, online CPUs, total memory, working directory and its filesystem/mount point, cgroup v2 controllers and user. `source`/`tools` are read from `git`, `rustc` and `podman` on `PATH` at run time; absent values mean the tool was unavailable where the runner executed, never a default.

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
| Source | Commit that introduced this file (the runner ran outside the checkout, so `source.git_commit` is absent in the record) |

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

## Reproducing

1. Prepare rootless Podman for a non-root user per [Development](development.md#linux-executor-work-f05f07-and-w03-onward) and pull the image by digest.
2. Build with `cargo release-linux` (or `cargo build --release -p sentinel-bench`) and copy `sentinel-bench` to a native-filesystem directory owned by that user.
3. As that user, run the direct baseline, then `podman system prune -f`, one `--warm-state cold --warmup 0 --samples 1` run, then warm runs with and without limits, all with `--output` to one file.
4. Commit the record under `bench/` and summarize it here with the host identity and any caveats.
