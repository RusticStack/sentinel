# Legacy Go pilot CI baseline

Measured 2026-09-13. This records what Legacy Go pilot's GitHub Actions setup did on the hardware Sentinel must beat. Numbers are from the raw records committed under [`bench/`](../bench/); nothing here is a Sentinel result.

**History.** Legacy Go pilot left the measurement set on 2026-10-22. This baseline stays as the record of the reference host's topology and measurement method and is not repeated. Current pilot baselines are taken by B01a ([pilot workloads](pilot-repositories.md#check-contracts-and-benchmarks)). Public source and host labels are anonymized; live repository and account details remain private.

## Physical topology behind the runner names

The historical self-hosted runners shared one virtualized x86_64 host:

| Item | Value |
|---|---|
| Host | `reference-host`, AMD EPYC 9645, 12 vCPUs (1 thread/core), 31 GiB RAM, virtio disk, ext4 |
| Kernel / runtime | Linux `7.0.0-31-generic`, rootless Docker 29.8.0 (overlayfs, systemd cgroup driver), Go 1.27.0 |
| Runner listeners | 16 across the measured workload and its related jobs; runner and account names are omitted from the public snapshot |
| cgroup caps | Primary slice: `cpu.max` 10 CPUs, `memory.max` 26 GiB. Secondary slice: 8 CPUs, 16 GiB. Sum of caps (18 CPUs) exceeds the 12 vCPUs |
| Throttling since boot (3.3 days) | Primary slice: 72,360 of 1,333,015 CFS periods throttled (5.4%), 6,628 s throttled, 200,458 CPU-s used. Secondary slice: 15,365 periods, 2,953 s throttled |
| Other runners | A separate arm64 host was not used by `ci.yml` |

Consequence: up to 14 jobs of one workload competed for 10 CPUs with no per-job limit. Concurrency across runs, not just within a run, set the tail.

## What 25 successful `ci.yml` runs look like

Source: [`bench/f06-legacy-go-ci-runs.jsonl`](../bench/f06-legacy-go-ci-runs.jsonl), the GitHub jobs/steps API for the 25 most recent successful runs (2026-09-10 to 2026-09-13). 22 ran on the VPS, 3 on GitHub-hosted `ubuntu-24.04`. Timestamps are GitHub's, at one-second resolution. Run "span" is first job created to last job completed and is unreliable for runs with re-run or skipped jobs (four spans under 150 s are such cases).

| Metric | Value |
|---|---|
| Run span, VPS (n=22) | median 591 s, p95 1,078 s, max 2,383 s |
| Run span, GitHub-hosted (n=3) | 961, 971, 1,291 s |
| Job queue wait, all jobs | median 2 s, p95 418 s, max 1,651 s |
| Peak parallel jobs per run | 2–4 before 2026-09-12 (four runners), 9–10 after (ten runners) |

Job durations, VPS and hosted combined (seconds):

| Job | n | median | p95 |
|---|---|---|---|
| test-race | 17 | 297 | 362 |
| integration | 25 | 273 | 350 |
| docker | 25 | 248 | 363 |
| test | 25 | 171 | 602 |
| coverage | 25 | 162 | 236 |
| sdk-nuxt | 18 | 154 | 211 |
| fuzz | 25 | 109 | 215 |
| supply-chain | 25 | 74 | 110 |
| playwright | 25 | 70 | 111 |
| lint | 25 | 44 | 187 |

Longest steps by median: `test-race / Test (race detector)` 288 s, `docker / Test docker-compose` 221 s, `integration` suite 103 s plus race pass 120 s, `test / Test (unit)` 70 s, `test / legacy JSON wire contracts` 68 s, `coverage` 75 s + 65 s, `fuzz` 54 s + 39 s. Setup steps are not free either: `docs / Setup Node` median 17 s, p95 124 s.

The critical path is three independent ~250–300 s jobs (`test-race`, `integration`, `docker`) plus whatever queue wait they suffer. Adding runners on 2026-09-12 raised parallelism from 4 to 10 but the median span stayed near 600 s, because those three jobs are individually long and now contend for the same 10 CPUs.

## Isolated versus concurrent commands on the same host

Source: [`bench/f06-vps-probe.log`](../bench/f06-vps-probe.log), produced by [`bench/f06-vps.sh`](../bench/f06-vps.sh) in the benchmark sandbox at Legacy Go pilot commit `0c87e018`, with the CI runners idle (load 0.3). CPU seconds and throttling are primary-slice cgroup deltas; per-process rusage was unavailable (no GNU `time`). Warm means a populated `GOCACHE` from the previous phase; the module cache was warm throughout.

| Phase | Wall | CPU-s | Throttled | Notes |
|---|---:|---:|---:|---|
| `go test -count=1` unit, cold `GOCACHE` | 98 s | 396 | 35 s | CI's `test` step equivalent after a cache miss |
| same, warm | 63 s | 122 | 1.6 s | test execution only; CI median is 70 s |
| same, warm, `-run '^$'` | 5 s | 47 | 1.5 s | link and start 83 test binaries, run nothing |
| `-race` unit, cold | 260 s | 839 | 15 s | |
| `-race` unit, warm | 216 s | 519 | 6.5 s | CI `test-race` median is 288 s |
| unit + race concurrently, warm | 72 s + 218 s | 628 | 32 s | unit +15%, race +1% versus isolated |

Separation of the unit lane (warm): about 5 s is build/link, about 57 s is test execution, and that execution uses only about 75 CPU-s, an average of 1.3 busy cores on a 10-core cap. It is **wait-dominated**, not CPU-bound: `internal/consensus` alone takes 59 s (three-node Raft tests with elections and restarts), `internal/web` 17 s, `docs` 9 s. Under `-race`, `internal/web` takes 193 s by itself and is the whole race critical path; `objectsvc` 65 s and `consensus` 60 s follow.

Compilation matters on a miss: cold minus warm is 36 s wall and 274 CPU-s for the unit lane and 44 s / 320 CPU-s for race. Actions' cache restore does not preserve `GOCACHE` reliably across runners here, so CI often pays this.

Two concurrent lanes cost little extra wall time, but throttling rose from 8 s to 32 s, showing the 10-CPU cap engaging. CI runs up to ten jobs at once, several of them Docker-heavy, so the p95 tail (test 602 s, lint 187 s, Setup Node 124 s) is consistent with contention rather than with the commands themselves.

## What this means for the sub-minute target

- The ~600 s median is not one slow thing. It is three ~250 s lanes whose length is set by a few wait-heavy packages, plus compile cache misses of 35–45 s, plus queue and contention tails.
- Sentinel-side wins available without touching tests: persistent per-toolchain `GOCACHE` (removes 36–44 s per lane on a miss), pre-extracted images and toolchains (removes Setup Node/Go steps), immediate dispatch, and per-job CPU reservations so ten jobs do not oversubscribe ten cores.
- Repository-side work is unavoidable for the last factor: `internal/web` under race (193 s) and `internal/consensus` (59 s) are single packages and cannot be parallelised by the CI engine. Sharding across packages already happens; these need shorter fixed waits or split test binaries. This is step 5 of the experiment sequence in [performance research](performance-research.md).
- The Docker/Compose (221 s) and integration (223 s) lanes were not profiled internally, and the probe was not repeated while a real CI run was executing.

## Reproducing

1. In a private checkout of the historical source, configure the benchmark host and sync the commit under test.
2. Run `bench/f06-vps.sh` in the benchmark sandbox and retain `f06/phases.log` with host-load provenance.
3. Export the chosen runs' jobs through the forge API and append the anonymized timing records to `bench/`.
4. Release any shared benchmark lease.
