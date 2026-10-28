# Benchmark contracts

Every Part 14 number is measured under a **frozen contract**. A contract is a JSON file (`sentinel.bench-contract/1`) that fixes what a representative check is and the conditions it is measured under. The runner refuses to measure when the host or the inputs differ from it, and every record names the contract revision and digest it was taken under. Records from two revisions are never compared.

**Publication snapshot.** Public contracts and records use anonymized source URLs and stable host labels; live mirror names, account names and deployment details are not published. Sanitization changes contract bytes, so the digest of a public snapshot is not the digest quoted by historical records. Measurements, revisions and timestamps are unchanged. Reproduction requires a private contract with equivalent inputs and real mirror URLs; records taken under it are a new series, never silently merged with the historical one.

## In force: `pilots-ci` revision 4

[`bench/contracts/pilots-ci.json`](../bench/contracts/pilots-ci.json), frozen 2026-10-24 (B01a in `TODO.md`), one lane per [pilot workload](pilot-repositories.md#check-contracts-and-benchmarks). Harness: [`bench/p14-pilot.sh`](../bench/p14-pilot.sh).

| Item | Frozen as |
|---|---|
| Reference host | `kvm-host`: AMD Ryzen 9 7900, 24 logical CPUs, at least 122 GiB, ext4, Podman 5.7.0 and cgroup v2. Sentinel and the GitHub baseline are pinned to separate six-core CCDs so they can run concurrently without sharing a CCD |
| Total allocation | 10 CPUs and 26 GiB per side. Concurrent jobs of one lane share it: the caps of jobs that can run together add up to at most 10 CPUs |
| Sources | Anonymized cli, ripgrep and gson mirror labels at `4f2cfe92`, `3fce3b5b` and `e2292f9c`; live URLs remain in private runner configuration |
| Images | `golang:1.27.3-trixie`, `rust:1.99.1-trixie`, `maven:3.9-eclipse-temurin-17`, `-21`, `-25`, each by digest |
| Lanes | `cli`: `go.yml` `build`, ubuntu row, as `examples/pilots/cli.sentinel.yml` (one job on 10 CPUs and 26 GiB: `go mod download`, `go test -race -tags=integration ./...`, `go build ./cmd/gh` with and without `ghdebug`); `ripgrep`: `ci.yml` `test`, stable row, as `examples/pilots/ripgrep.sentinel.yml`; `gson`: `build.yml` `build` on JDK 17, 21 and 25, as `examples/pilots/gson.sentinel.yml`. Each is the fork's live pipeline, run on an egress worker |
| Not measured | cli's Windows and macOS rows, `integration-tests` and acceptance (both need a GitHub token), lint, govulncheck and CodeQL; ripgrep's other matrix rows, the zsh completion step, wasm, rustfmt and docs; gson's JDK 11 and JDK 25 jmods rows, `build-gson-subset`, API/Android compatibility, CodeQL, fuzz and scorecard |

| Condition | Procedure |
|---|---|
| `cold` | Worker cache directory removed and the worker restarted; images present. Dependencies are downloaded by the job through the worker's operator-granted egress, as a GitHub job downloads them, so a cold sample depends on the network and is reported with that |
| `warm` | Unchanged tree (an empty commit); caches kept from the previous sample of the same lane, after one unrecorded warm-up |
| `small-edit` | One line appended to a compiled source of the lane's main package (cli `internal/ghcmd/cmd.go`, ripgrep `crates/searcher/src/lib.rs`, gson `JsonNull.java`), caches kept |

Freshness: every required test runs on every sample (the cli lane sets `GOFLAGS=-count=1`, stricter than the workflow, whose restored `GOCACHE` can serve results; `cargo test` and `mvn verify` always run); build caches are kept, test results never are. A sample counts only when every job passes. Comparisons use records from the reference host with CPU pressure (`some`, avg60) under 2 % at the start of each sample, at most 30 days old.

**Current B08 assessment (2026-10-24): unmet.** The largest recorded GitHub baselines are 109 s (cli), 88 s (gson) and 30 s (ripgrep), so no lane has the required >=300 s baseline. Sentinel warm nearest-rank p95 over ten non-warmup samples is 64.08 s (cli), 44.02 s (gson) and 21.39 s (ripgrep), computed from `bench/p14-pilot-*.jsonl`. These small samples are development evidence, not a release-grade tail. Do not change the baseline threshold or substitute another comparison to close B08.

## B11: the 2× Blacksmith gate

B11 is the primary relative target and uses a separate frozen contract, not a reinterpretation of revision-4 GitHub self-hosted records. For every selected lane and condition, `Sentinel trigger-to-required-check p95 / Blacksmith trigger-to-required-check p95 <= 0.50`.

- Use identical source SHA, commands, assertions, freshness policy, required jobs/artifacts and resource envelope. Keep cold, warm and small-edit series independent.
- Interleave 100 paired release samples per lane/condition. Publish raw samples, distributions and variance, plus a one-sided 95% bootstrap upper confidence bound on the paired log-duration ratio below 0.50. Smaller samples may guide optimization but cannot pass the release gate.
- Count any incorrect or failed required check as a gate failure; never remove failures to improve the distribution. Report job-start-to-finish and phase costs beside the end-to-end clock.
- Use actual Blacksmith executions and timestamps. Disclose hosted hardware/network differences and call the result a hosted-service comparison, not a same-hardware architectural win, when equivalent hardware cannot be provided.
- Vendor multipliers, GitHub self-hosted results and the one-run Blacksmith startup probe are not B11 evidence. **Blocked by: Blacksmith benchmark access.** Part 24 and V06 remain open until B11 passes.

### The frozen B11 contract and harness

[`bench/contracts/b11-blacksmith.json`](../bench/contracts/b11-blacksmith.json) (`sentinel.b11-contract/1`, revision 1, frozen 2026-10-28) fixes the rules above before any sample exists; it holds no measurement. The harness is `sentinel-b11` (`crates/sentinel-bench/src/bin/sentinel-b11.rs`):

```
sentinel-b11 --contract bench/contracts/b11-blacksmith.json --samples pairs.jsonl [--output report.jsonl]
```

- **Samples** (`sentinel.b11-samples/1`, JSON lines). The first line names the contract and revision (`{"format", "contract", "revision"}`); samples taken under another revision are refused, never combined. Each following line is one pair: `lane`, `condition`, `pair` (0, 1, 2, ... within the series), `order` (`sentinel-first` in even pairs, `blacksmith-first` in odd ones: the ABBA interleave), and a `sentinel` and a `blacksmith` execution, each with `sha`, `trigger_to_required_ns`, `outcome` (`pass`, `fail`, `incorrect`) and optionally `job_ns` (first job start to last job finish) and `phases` (name to nanoseconds). Both clocks are GitHub's recorded trigger and last-required-check completion (the contract's `clock`). A duration of 0, an unknown lane or condition, a duplicate pair, an unknown field or a malformed SHA is an input error (exit 2, no report).
- **Statistic.** Per pair `ln(sentinel / blacksmith)`. The gate needs the nearest-rank p95 of Sentinel over that of Blacksmith at most 0.50 **and** the one-sided 95% upper bound of the mean paired log ratio, from a percentile bootstrap over pairs (10,000 resamples, xoshiro256** seeded with the contract's seed, so a report is reproducible byte for byte), strictly below `ln 0.50`. The bootstrap upper bound of the p95 ratio itself is reported beside the gate and does not decide it.
- **Verdict per series** (lane and condition, independent). `pass`; `fail` when any execution on either side has outcome `fail` or `incorrect` (it stays in every distribution, nothing is dropped), a pair ran different SHAs, the ABBA order is broken, pair numbers have a gap (a dropped pair), or a ratio condition above is not met; `insufficient` below 100 pairs (the figures are still reported, as optimization guidance). A contract series with no samples fails the whole gate (`missing`). The exit code is 0 only when every series passes, 1 for any other verdict, 2 for an input error.
- **Report** (`sentinel.b11-report/1`, one JSON line): the contract id, revision and BLAKE3, the label `hosted-service comparison` (never same-hardware), per series both sides' distributions (count, min, median, p95, max, mean), the paired ratios in pair order, the ratio estimates and bounds, the failure counts, and `job_ns` and each phase for both sides beside the end-to-end clock (a missing figure is absent, never zero).

The contract also records, without freezing any number, the `freshness` policy per condition, the `required_outputs` rule, the `failure_counts` a report states (pass, fail, incorrect and censored per series and side) and two deliberately unfilled blocks: `resource_envelope` (vCPU, memory and disk for Sentinel and Blacksmith, all `null`) and `hosted_hardware_disclosure_fields` (the hardware, region and network facts every release report must state). Neither is filled until Blacksmith runner sizes are known; a guessed value would be a weakened gate. The harness ignores these blocks; filling them is a contract revision made before the first release sample.

Status: the harness is exercised only by synthetic data and the collector's plumbing dry run ([below](#the-b11-collector); `crates/sentinel-bench/tests/b11.rs` and its unit tests). No Blacksmith sample exists, so B11 has no result; the lane selection for the release gate is a revision of this contract made before the first release sample.

### The B11 collector

`bench/b11-collect.py` produces the samples the harness reads, extending `bench/b01a-github.py` (it reuses its `gh api` plumbing). It takes no measurement of its own: every clock is a timestamp GitHub records, for both sides.

```
python bench/b11-collect.py collect LANE CONDITION PAIRS [--config FILE] [--records FILE] [--start N] [--no-warmup]
python bench/b11-collect.py pairs RECORDS... [--dry-run] [--output FILE]
python bench/b11-collect.py replay LANE [--baseline FILE] [--output FILE]
```

- **One pair is one commit.** `collect` makes a fresh commit per pair (an empty commit for cold and warm; for small-edit one marker line in the lane's compiled source, replaced each pair so the edit stays one line) on a worktree of its own, and pushes that SHA to the Sentinel mirror and to the Blacksmith-backed mirror back to back. The first of the two alternates every pair (Sentinel first in even pairs, ABBA). The two sides must be two repositories, or a single push would trigger both at once. A pair completes before the next one starts. Warm and small-edit series start with one unrecorded warm-up pair (`warmup: true`, never paired); cold has none. Per-side `prepare` hooks (argv lists in the config) run before the pushes, for removing worker caches or rotating Blacksmith's cache scope; the collector does not know how either side keeps its caches.
- **The clock** is the check suite's `created_at` of the side's app (the instant GitHub records for the push) to the latest `completed_at` among the side's named required check runs. This relies on GitHub creating the app's check suite at the push (the default automatic check-suite creation for an app with `checks: write`); an app that disabled it would get its suite only when it first posted a check, which would hide delivery latency inside the trigger. That has not been confirmed against the Sentinel app and must be before a live series counts. Because the SHA is unique to the pair on each mirror, the checks GitHub shows for it are that execution's. `job_ns` is that last completion minus the earliest required-check start; the `queue` (trigger to first start) and `run` phases split it. GitHub's stamps have one-second resolution (`resolution_ns` in each record), so a figure that rounds to zero is left out, never written as 0, and short lanes carry up to a second of quantization on each side.
- **Outcomes.** All required checks `success` is `pass`; any `failure`, `cancelled`, `timed_out` or similar is `fail`; a required check that is `skipped` or `neutral` is `incorrect` (it did not run its assertions). A required check that has not completed when the timeout (`timeout_seconds`, default 1800) ends is `fail` with `censored: true`, and its duration is the observation window, a lower bound. Nothing is dropped: every outcome reaches the harness and fails the gate there.
- **Provenance** is anonymized labels only: the side label, host label, build label, vCPU and memory envelope, the cache state per condition, and the collector's commit. A label that is not lowercase words (a repository, an address, an account) is refused. Repositories, remotes and hooks stay in the config named by `SENTINEL_B11_CONFIG` (default `.local/b11-config.json`, git-ignored; the shape is `bench/b11-config.example.json`).
- **`pairs`** refuses an unpaired or duplicated execution, an order the two sides disagree on, records of another contract revision or lane, and any mix of dry-run and live records; dry-run records pair only with `--dry-run`. A SHA mismatch or a failure is passed on unchanged for the harness to report.
- **The dry run.** `replay` reads the committed GitHub self-hosted baselines (`bench/b01a-github-{cli,ripgrep,gson}.jsonl`, warm, the warm-up excluded) through the same extraction, using each run's jobs as its required checks, and writes records labelled `dry_run` whose two sides are that one recorded run. [`bench/b11-dryrun-records.jsonl`](../bench/b11-dryrun-records.jsonl) and [`bench/b11-dryrun-samples.jsonl`](../bench/b11-dryrun-samples.jsonl) are that output (5 pairs per lane). They prove the plumbing: the extraction reproduces `push_to_last_job_s` of the baseline for every run without skipped jobs, the records pair, and `sentinel-b11` reads them (the harness test pins 5 pairs per lane, verdict `insufficient`, p95 ratio exactly 1.0 by construction, the other six series missing). They are not a ratio, not Blacksmith data and not evidence of any speed.

Status: the extraction, outcome rules, ABBA pairing, commit construction and censoring are exercised by `bench/test_b11_collect.py` on canned GitHub payloads. The live path (pushing to two mirrors, reading a real Sentinel app's check suite and a real Blacksmith-backed workflow) has not run: it needs the Sentinel GitHub App installed on a mirror, a Blacksmith-backed mirror and workflow, and the lane selection of a contract revision. **Blocked by: Blacksmith benchmark access.** No Blacksmith result is produced or claimed.

## The runner

`sentinel-bench --contract FILE --lane ID --condition cold|warm|small-edit --root DIR --runtime scoped|podman` behaves as follows:

- It loads the contract and checks the host (CPU model, CPU count, memory), the Podman version, the image digest and that each source holds its pinned commit. Any difference is a refusal that lists every mismatch. Nothing is measured and nothing is written.
- It runs the condition's preparation before each run. The small-edit nonce changes every sample.
- It runs the lane under the contract's allocation unless `--cpus`/`--memory` say otherwise, and records the toolchain the measured runtime actually runs.
- Its record adds `contract {id, revision, blake3, lane, condition, cpu_pressure_avg60, sources, image}` and `toolchain` to the [record format](benchmarking.md#record-format-sentinel-bench1).
- It refuses to start when CPU pressure (`some`, avg60) is 5 % or more.

## Revision history

- **`b11-blacksmith` revision 1** (2026-10-28): the separate B11 contract and paired-sample harness, rules only; no samples exist ([above](#the-frozen-b11-contract-and-harness)).

- **`pilots-ci` revision 4** (2026-10-24): moved the reference measurement to `kvm-host`, with Sentinel and the GitHub baseline pinned to separate CCDs and allowed to run concurrently. Revision 3 completed no record on `reference-host`.

- **`pilots-ci` revision 3** (2026-10-24): replaced the bbolt Go lane with cli's `go.yml` Ubuntu `build` row. The earlier fsync-heavy suite ran about 50 minutes per sample and kept failing for host reasons rather than Sentinel's.

- **`pilots-ci` revision 2** (2026-10-22): the online lanes with bbolt's `Tests AMD64` workflow as the Go lane, with unit jobs capped at 4 GiB. A bbolt unit job was OOM-killed at 4.1 GiB and the ripgrep and gson samples never started after worker enrollment expired, so no record completed.

- **`pilots-ci` revision 1** (2026-10-22): the bbolt, ripgrep and gson lanes run offline from vendored dependencies (`bench/pilots/`, since removed). Its only samples, the first ripgrep run (about 53 s cold and 40–48 s warm, not a committed record), are history and are not compared with later revisions.
- **`legacy-go-ci` revision 1** (2026-09-28, [`bench/contracts/legacy-go-ci.json`](../bench/contracts/legacy-go-ci.json)): the first contract, on Legacy Go pilot's `ci.yml` required lanes on the same host ([CI baseline](ci-baseline.md)). B01, B02 and B04 were measured under it; everything below is its record, kept as history and never re-run or compared with pilot records. The file stays as the fixture of `crates/sentinel-bench/src/contract.rs`'s test.

### What `legacy-go-ci` fixed

| Item | Frozen as |
|---|---|
| Reference host | reference-host VPS: AMD EPYC 9645, 12 vCPUs, 31 GiB RAM, ext4, Ubuntu 26.04 (kernel 7.0), Podman 5.7.0, cgroup v2 with the bench user's systemd manager holding cpu, memory and pids (`loginctl enable-linger`). This is the host Legacy Go pilot's runners used and Sentinel's verification host |
| Total allocation | 10 CPUs and 26 GiB: the caps of the `legacy-go-ci` runner slice. A lane measured alone gets all of it, and lanes measured together share it. Every runtime compared gets the same caps (below) |
| Sources | Legacy Go pilot `cbe48fc7` (full history), `legacy-go-pilot-sdk-node` `bccad4c8` and `legacy-go-pilot-sdk-java` `37c921f6`. The repositories are private, so the host receives them as git bundles |
| Images | `golang:1.27.1-trixie@sha256:7bffdb40…`. Go 1.27.1 with `GOTOOLCHAIN=local`, gcc 14.2 for the race detector's cgo |
| Tools | The versions Legacy Go pilot's Makefile pins: staticcheck 0.8.1, golangci-lint 2.13.2, govulncheck 1.8.0, cyclonedx-gomod 1.12.0 (the superseded 2026-09-13 migration review quoted older ones) |
| Environment | Legacy Go pilot's CI environment: `GOTOOLCHAIN=local`, the file-first `GOPROXY` over the checked-in `.goproxy`, and the SDK directories. Build cache, module cache, `GOPATH` and temporary directory sit under the bench root |
| Lanes | `unit`, `unit-legacy-json`, `vet-build`, `race`, `integration`, `integration-race`, `gofmt`, `coverage` and `fuzz`, each with `ci.yml`'s exact command. `-count=1`, `-race`, both 30-second fuzz budgets and the integration suite's own process are kept |
| Not measured, with the reason | staticcheck and golangci-lint (they install tools from the network on a miss), supply-chain (reads a live vulnerability database), docker/Compose (an optional lane kept external), Node, browser and advisory lanes, and the long acceptance, chaos, production and release scopes (reported separately, never inside the sub-minute target) |

### Conditions

| Condition | Procedure (unmeasured, before every sample) | Samples |
|---|---|---|
| `cold` | Sources at the pinned commits, and the image present (a pull is measured apart). Build cache, module cache and tool binaries emptied; the module cache is made writable first, because Go makes it read-only. Modules that the checked-in `.goproxy` lacks come from `proxy.golang.org`, as they do in CI after a miss, so a cold sample depends on the network | 3 |
| `warm` | Unchanged source at the pinned commit. Caches are kept from the previous sample, and one unrecorded warm-up primes them. Tests still run: `-count=1` | 10 |
| `small-edit` | Warm caches plus a fresh edit per sample: an inert unexported declaration appended to `internal/s3/cors.go`, different each time. The package recompiles and every test binary depending on it relinks | 10 |

### Freshness

- Every required test runs on every sample: `-count=1` is in every command, and no test result is reused.
- A sample counts only when the lane exits 0. A failing sample aborts the record.
- Changing any frozen item makes a new revision.
- A record is valid for comparison for 30 days, on the reference host, taken under the same revision. The contract digest in the record settles which revision that was.
- The runner refuses to start when CPU pressure (`some`, avg60) is 5 % or more. `bench/b01-measure.sh` waits for it to drop under 2 % before each step, so one lane's load never leaks into the next.

### Identical isolation

The `scoped` runtime runs the workload as a direct process in a systemd user scope holding the same caps a container gets:

| Cap | Podman | Scoped |
|---|---|---|
| CPU | `--cpus N` (`cpu.max` N×100000/100000) | `CPUQuota=N×100%` (the same `cpu.max`) |
| Memory | `--memory M --memory-swap M` (no swap) | `MemoryMax=M`, `MemorySwapMax=0` |
| Paths and user | The bench root mounted at its own path, `--userns=keep-id` | The same files as the same user |
| Network | `--network=host` | The host's |
| Toolchain | The image's `/usr/local/go` | The same directory, copied out of the image by `bench/b01-setup.sh` |

Both were verified on the reference host by reading `cpu.max`, `memory.max` and `memory.swap.max` from inside each. One difference remains: a scoped cgo build links with the host's C compiler (gcc 15.2) rather than the image's (14.2). Each runtime has its own bench root, so caches never mix.

### Results

Record: [`bench/b01-isolation.jsonl`](../bench/b01-isolation.jsonl), taken 2026-09-28 on the reference host. Every lane record carries contract revision 1, the original contract BLAKE3 prefix `b0415e063bb9…`, CPU pressure 1.55–1.95 % at its start, and `go1.27.1` as both runtimes report it. That digest identifies the original bytes, not the anonymized publication snapshot. The runner was built from `db9e664` plus the uncommitted B01 changes (`git_dirty: true`) recorded at the time.

**The Part 01 no-op floor, extended with identical isolation** (20 samples each, 2 warm-ups):

| Runtime | Caps | min | median | p95 | max |
|---|---|---|---|---|---|
| direct | none | 0.7 ms | 0.8 ms | 1.3 ms | 1.6 ms |
| scoped | 1 CPU, 256 MiB | 9.3 ms | 11.7 ms | 19.4 ms | 34.2 ms |
| podman | 1 CPU, 256 MiB | 336.5 ms | 354.7 ms | 363.5 ms | 397.6 ms |
| scoped | 10 CPUs, 26 GiB | 9.6 ms | 11.0 ms | 12.7 ms | 13.2 ms |
| podman | 10 CPUs, 26 GiB | 331.4 ms | 361.1 ms | 384.3 ms | 386.5 ms |

**The contract's `unit` lane** (Legacy Go pilot `ci.yml` `test` unit step: every non-integration package, `-count=1`), 10 CPUs and 26 GiB:

| Condition | Runtime | n | min | median | p95 | max |
|---|---|---|---|---|---|---|
| cold | scoped | 3 | 93.3 s | 97.3 s | 99.2 s | 99.2 s |
| cold | podman | 3 | 92.2 s | 92.3 s | 96.8 s | 96.8 s |
| warm | scoped | 10 | 62.4 s | 64.1 s | 70.7 s | 70.7 s |
| warm | podman | 10 | 64.0 s | 66.0 s | 70.0 s | 70.0 s |
| small-edit | scoped | 10 | 63.0 s | 66.7 s | 71.5 s | 71.5 s |
| small-edit | podman | 10 | 59.7 s | 64.8 s | 67.9 s | 67.9 s |

Interpretation, limited to what was measured:

- Isolation costs about **0.35 s per run** in a container, against about 10 ms for the same caps in a systemd scope. The cost does not depend on the size of the caps. Part 01's unlimited container start on this host was 428 ms ([the F05 VPS record](benchmarking.md#the-same-baseline-on-the-verification-vps)).
- On the `unit` lane, **the runtime makes no difference that the samples can resolve**. The warm medians differ by 1.9 s and the small-edit medians by 1.9 s in the other direction, inside a 6–8 s spread between min and max. The lane is not bound by isolation.
- **Warm unchanged source is about 64–66 s, and a small edit costs no more.** Legacy Go pilot's F06 probe found this lane wait-dominated (`internal/consensus` alone takes about 59 s). A cached build cannot shorten tests that `-count=1` runs every time, so the remaining time is the tests themselves. That is where B04 looked; B07 now works on the pilots' own lanes.
- Cold is about 28–31 s slower than warm: compilation plus the module downloads the checked-in proxy lacks. The cold samples depend on the network, and three samples are only indicative.
- The lane's warm time is the same order as CI's `test` step median of 70 s ([CI baseline](ci-baseline.md)). The sub-minute target cannot be met by the engine alone for this lane.

### B02: the same lane through each executor

The contract's `unit` lane measured through four executors on the reference host, each under the contract's 10 CPUs and 26 GiB, on 2026-09-29. Warm-up runs are excluded. Hosted Blacksmith and Depot runners were **not** measured: there is no account for either, so there is no comparison, and vendor speed-up claims are not Sentinel evidence.

| Executor | What the clock covers | Record |
|---|---|---|
| Direct, scoped (B01) | the test command only, in a systemd scope with the caps | [`b01-isolation.jsonl`](../bench/b01-isolation.jsonl) |
| Podman (B01) | the test command in a container, same caps | same |
| Woodpecker 3.18.1, `woodpecker-cli exec` | spawn to exit of a one-step local pipeline, with its Docker backend on the bench user's rootless Podman socket and `--backend-docker-limit-*` set to the caps. No clone (the bench root is mounted), and caches are the mounted directories | [`b02-woodpecker.jsonl`](../bench/b02-woodpecker.jsonl) |
| GitHub self-hosted runner 2.337.0 | per step and per job from the Actions API (1-second resolution). The run was created by a push, and the job repeats `ci.yml`'s `test` job up to its unit step: checkout from github.com, `setup-go` (tool cache, no remote cache), both SDK checkouts at the pinned commits, `go mod download`. The runner ran as a systemd user service with the caps, on Legacy Go pilot's repository, labelled only `sentinel-b02` | [`b02-github-runner.jsonl`](../bench/b02-github-runner.jsonl) |
| Sentinel (`7966853`) | the intake event after a git push, to the run finished (the wait API), and each attempt phase from `GET /attempts/{id}/steps`. The source is served over loopback HTTPS through a bound repository with a sealed credential; the Go module store and build cache are Sentinel caches | [`b02-sentinel.jsonl`](../bench/b02-sentinel.jsonl) |

**Medians (p95), seconds:**

| Executor | warm | small-edit | cold (n=3) |
|---|---|---|---|
| Direct, scoped: test | 64.1 (70.7) | 66.7 (71.5) | 97.3 (99.2) |
| Podman: test | 66.0 (70.0) | 64.8 (67.9) | 92.3 (96.8) |
| Woodpecker: whole exec | 67.4 (71.4) | 67.4 (75.5) | 94.8 (95.3) |
| GitHub runner: unit step | 64 (70) | 70 (75) | 91 (97) |
| GitHub runner: job | 75 (81) | 81 (86) | 106 (114) |
| GitHub runner: queue before the job | 2 (3) | 2 (3) | 2 (2) |
| Sentinel: test step | 66.2 (70.3) | 66.1 (71.2) | 95.0 (98.6) |
| Sentinel: intake to finished | 77.6 (81.3) | 78.0 (83.0) | 105.9 (110.3) |

**Sentinel's phases, warm medians:** intake to run dispatched 4.23 s, checkout 1.77 s, image pull 1.03 s (a registry manifest check; the image is present), container start 0.31 s, test step 66.15 s, finalize 2.95 s (cache publication). That leaves about 1.1 s unaccounted, for placement, the offer and the report. Both caches hit on every warm and small-edit run; cold runs had none (`unavailable`, their entries removed).

Differences the numbers carry:

- **Sources.** The GitHub runner checks out from github.com over the network. Woodpecker and the direct runs use the checkout in place. Sentinel's jobs have no network egress and no extra checkouts, so its bench source is Legacy Go pilot `cbe48fc7` plus the two SDK trees vendored under `sdk-checkouts/`, `.goproxy` completed from a warm module cache of the same `go.sum`, and the pipeline ([`b02-sentinel.yml`](../bench/b02-sentinel.yml)). The test command, image, caps and SDK bytes are the same. The cold samples therefore differ: Sentinel's read modules from the local proxy, while the others fetched those missing from `.goproxy` over the network.
- **Users.** Woodpecker and Sentinel run the step as uid 0 inside a rootless container (the bench user outside). Podman in B01 kept the user's own uid, and the GitHub runner and scoped runs ran directly as the bench user.
- **Clock start.** GitHub's job clock starts at run creation, after GitHub received the push. Sentinel's starts at the intake event, after the push. Woodpecker's has no source step at all.

What the measurements say:

- **The lane is test-bound.** Every executor spends 64–67 s in the same `go test -count=1`, and no engine changes that. The sub-minute target for this lane needed the test time itself to shrink, not only the engine; B07's equivalent work is on the pilots.
- **Engine overhead is about 11 s for both Sentinel and a healthy self-hosted runner.** Sentinel is not faster than the GitHub runner on this lane today: 77.6 s against 75 s of job plus about 2 s of queue. Woodpecker's exec adds 1–3 s over a bare container because it does no source or cache handling.
- **Sentinel's overhead, in order of size:** 4.2 s from intake to dispatch (the controller resolves the pipeline at the pushed revision through Git before creating the run), 3.0 s of cache publication in finalize, 1.8 s of checkout, and 1.0 s of registry manifest check per job. These are B04's first targets.

### B04: the critical path, profiled and cut

B02's phase record ([`b02-sentinel.jsonl`](../bench/b02-sentinel.jsonl)) is the profile of Sentinel's own path on the contract lane. The test step (64–67 s) is the lane's own work, the same in every executor; it is wait-dominated inside a few Go packages ([CI baseline](ci-baseline.md)) and was out of the engine's reach. Around it, Sentinel spent about 11 s per warm run. In order of size:

| Phase (warm median) | Before | What it was |
|---|---|---|
| Intake → dispatch | 4.23 s | resolving `.sentinel.yml` at the pushed commit: a depth-one fetch of the whole tree to read a 1.5 KB file (the fetch's own time and byte count were not recorded; see below) |
| Finalize | 2.95 s | publishing the Go caches |
| Checkout | 1.77 s | the worker's mirrored checkout |
| Image pull | 1.03 s | a registry manifest request for an image already resident (fixed in [B03](latency-budgets.md#before-and-after-the-two-fixes)) |
| Container start | 0.31 s | |

**Pipeline resolution.** The controller reads the pipeline through a partial clone: the commit and its trees (`--filter=blob:none`), then the pipeline's own blob by its id. What the records show is the phase it sits in: intake → dispatch fell from 4.23 s (median of 10 warm B02 runs) to 0.48 s (median of 4 warm runs after the change). The isolated fetch figures quoted when the change was made (3.6 s and 75 MB before, 0.3 s and 0.2 MB after) appear in the commit message only, with no raw output committed: **not recorded in the repo**, so they are not evidence here; re-measure them with the fetch alone, on the reference host, before citing them. A server that ignores the filter sends everything, and a failure anywhere on the partial path falls back to the whole depth-one fetch, so every server still works (`sentinel-git` `file_at`; test `a_filtering_server_sends_only_the_pipeline_blob`). The bench repository's server has `uploadpack.allowFilter` enabled, as GitHub's does. At the time of this historical record, pull-request resolution through a merge ref still fetched the whole tree; B03a later moved it to the same blob-less partial-clone path. Current-tree revalidation is required before treating the B03-family figures as current.

**After** ([`b04-pipeline-fetch.jsonl`](../bench/b04-pipeline-fetch.jsonl), 4 warm samples and a warm-up, same lane, host and caps):

| Phase (warm) | Before | After |
|---|---|---|
| Intake → dispatch | 4.23 s | 0.48–0.50 s |
| Image pull | 1.03 s | 0.05–0.07 s |
| Checkout | 1.77 s | 1.79–1.87 s |
| Finalize | 2.95 s | 2.77–3.55 s |
| Everything but the test step (intake to finish, less the step's own time) | 10.9 s (median of 10 warm B02 runs, 10.5–11.4 s) | 7.3 s (median of 4, 7.1–8.0 s) |

The "after" column is four samples, so no tail is claimed. The runs carry no build commit or host block (records carry them since; see [benchmarking](benchmarking.md#record-format-sentinel-bench1)): the commit that added each file is the only attribution.

Sentinel's overhead on this lane is about 7.3 s against a healthy self-hosted runner's 11 s, plus its queue (B02). What remains, in order: cache publication in finalize (about 3 s), checkout (about 1.8 s), then dispatch and reporting (about 1.5 s together). **CPU throttling and disk wait were not profiled in this record** (neither the cgroup's throttled time nor I/O pressure was recorded for any phase). The argument that the step's time is the same in every executor says the step is not an engine difference; it does not show that throttling or disk wait cost nothing in Sentinel's own phases (checkout, cache publication). That part of B04 is split out as B04a in `TODO.md`; the assessment below covers what has been recorded since.

**Closure check (B04, 2026-10-28).** The record was rechecked against the repository. The code exists: `sentinel-git` reads the pipeline through a promisor `origin` with `blob:none` and falls back to the depth-one fetch (`crates/sentinel-git/src/unix.rs`), and `a_filtering_server_sends_only_the_pipeline_blob` and its merge-ref twin exist in `crates/sentinel-git/tests/file_at.rs`. Both artifacts exist: [`bench/b02-sentinel.jsonl`](../bench/b02-sentinel.jsonl) (10 non-warm-up warm runs) and [`bench/b04-pipeline-fetch.jsonl`](../bench/b04-pipeline-fetch.jsonl) (4 plus a warm-up). Recomputed from them: intake to dispatch 4.23 s to 0.48 s (medians), overhead around the test step 10.91 s (10.49–11.41) to **7.33 s** (7.14–8.00). An earlier text quoted 7.2 s for the "after" overhead; the median of four runs is 7.33 s, the figure above. Residuals that keep the ledger entry open: the isolated fetch figures (3.6 s and 75 MB to 0.3 s and 0.2 MB) have no committed raw output and are not evidence; the two records carry no build commit or host block; the "after" column is 4 samples; and disk wait and throttling are B04a.

### B04a: disk wait and CPU throttling, assessed

Records: [`bench/p14-b04a-cli.jsonl`](../bench/p14-b04a-cli.jsonl) and [`bench/p14-b04a-ripgrep.jsonl`](../bench/p14-b04a-ripgrep.jsonl) (contract `pilots-ci` revision 4, `warm`, one warm-up and five samples each, all jobs passed, build `3572006d` clean, reference host, CPU pressure avg60 0.46–1.75 % at the start). Produced by [`bench/b04a_profile.py`](../bench/b04a_profile.py) under `B04A_PROFILE`; reducer and summary tests are in [`bench/test_b04a_profile.py`](../bench/test_b04a_profile.py). Summary: `b04a_profile.py summarize FILE`; medians over the five samples below. Host pressure is machine-wide: the GitHub baseline runs on the other CCD and a concurrent run is not excluded by the record, so a stall is an upper bound for Sentinel's own share.

| Phase (median) | cli time | cli I/O stall (`full`) | ripgrep time | ripgrep I/O stall (`full`) |
|---|---|---|---|---|
| prepare (checkout, image, restore) | 3.01 s | 0.13 s | 1.23 s | 0.08 s |
| checkout | 0.46 s | 0.01 s | 0.10 s | 0.001 s |
| container start | 0.26 s | 0.11 s (41 %) | 0.26 s | 0.06 s (22 %) |
| steps | 56.08 s | 0.47 s (0.8 %) | 17.81 s | 0.80 s (4.5 %) |
| finalize (cache publication) | 4.35 s | 0.29 s (6.8 %) | 2.22 s | 0.19 s (8.4 %) |

What this shows. Steal is 0 and memory stall is about zero in every phase. CPU `some` stall is 1.1 % of the cli step and 3.0 % of the ripgrep step, and negligible elsewhere. Disk wait is small for the lane (at most 8 % of finalize) except container start, where a quarter to two fifths of the 0.26 s is I/O stall; that phase is 0.26 s in total. Cache publication writes 214 MB (cli) and 967 MB (ripgrep) in finalize with the device busy 450 ms and 758 ms of 4.35 s and 2.22 s. On these two lanes neither stall explains the 3–4 s finalize; it is copy and hash work.

What it does not show. **CPU throttling is not measured.** No record has `throttled_us` or `throttled_periods` for any phase: the worker scope has no `cpu.max` (`worker_cpu_quota_cpus` null), and the container scope was never attached to the step window. All 12 records saw four containers in the run, a window with more than one container is deliberately not guessed between, and only one record (ripgrep sample 5) reports a container quota (10 CPUs, the job's cap). The 10-CPU job cap therefore went unobserved at the cgroup where throttling would show.

Remaining phases and lanes, all required before B04a closes:

1. **Throttling in the step window**: attribute the container scope to the step window (one container per step, or tag the step's container) so `cpu.stat` throttled time and periods are present for the cli and ripgrep steps.
2. **gson**: no B04a record exists for `build-jdk17`, `-21` and `-25`.
3. **Conditions**: only `warm` was profiled; `cold` (where checkout and cache restore are largest) and `small-edit` have no profile.
4. **Cache publication under load**: finalize was profiled only while the host was quiet. Whether the container-start stall grows with a concurrent baseline job is open.
5. **Sample size**: five samples give no tail (every `p95` is the maximum, flagged `p95_is_max`).

B04a stays open for these reasons.

### Reproducing

These steps reproduced the revision-1 Legacy Go pilot records; they are kept as the procedure's record, not as an instruction to run Legacy Go pilot. A pilot contract replaces step 2's bundles with the pilot's pinned commit.

1. Configure an unprivileged benchmark account with a systemd user manager and delegated cpu, memory and pids controllers.
2. Put git bundles of the three sources in a directory the account can read. Build `sentinel-bench` (`cargo build --release -p sentinel-bench`) and copy it, `contracts/` and the two scripts into a kit directory.
3. Run `bench/b01-setup.sh ~/b01-scoped BUNDLES` and `bench/b01-setup.sh ~/b01-podman BUNDLES` as that account.
4. Run `bench/b01-measure.sh KIT OUT` detached (the historical series took about two hours). Keep the resulting records as a new series with the actual contract digest.
