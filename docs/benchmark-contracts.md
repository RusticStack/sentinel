# Benchmark contracts (B01)

Every Part 14 number is measured under a **frozen contract**. A contract is a JSON file (`sentinel.bench-contract/1`) that fixes what a representative check is and the conditions it is measured under. The runner refuses to measure when the host or the inputs differ from it, and every record names the contract revision and digest it was taken under. Records from two revisions are never compared.

The contract for the sub-minute target is [`bench/contracts/lockwell-ci.json`](../bench/contracts/lockwell-ci.json): Lockwell's `ci.yml` required lanes on the host its GitHub runners used ([CI baseline](ci-baseline.md), [Lockwell migration](lockwell-migration.md#performance-and-cutover-gates)).

## What the contract fixes

| Item | Frozen as |
|---|---|
| Reference host | netcup VPS: AMD EPYC 9645, 12 vCPUs, 31 GiB RAM, ext4, Ubuntu 26.04 (kernel 7.0), Podman 5.7.0, cgroup v2 with the bench user's systemd manager holding cpu, memory and pids (`loginctl enable-linger`). This is the host Lockwell's runners used and Sentinel's verification host |
| Total allocation | 10 CPUs and 26 GiB: the caps of the `lockwell-ci` runner slice. A lane measured alone gets all of it, and lanes measured together share it. Every runtime compared gets the same caps (below) |
| Sources | Lockwell `cbe48fc7` (full history), `lockwell-sdk-node` `bccad4c8` and `lockwell-sdk-java` `37c921f6`. The repositories are private, so the host receives them as git bundles |
| Images | `golang:1.27.1-trixie@sha256:7bffdb40…`. Go 1.27.1 with `GOTOOLCHAIN=local`, gcc 14.2 for the race detector's cgo |
| Tools | The versions Lockwell's Makefile pins: staticcheck 0.8.1, golangci-lint 2.13.2, govulncheck 1.8.0, cyclonedx-gomod 1.12.0 (the [migration notes](lockwell-migration.md) quote older ones) |
| Environment | Lockwell's CI environment: `GOTOOLCHAIN=local`, the file-first `GOPROXY` over the checked-in `.goproxy`, and the SDK directories. Build cache, module cache, `GOPATH` and temporary directory sit under the bench root |
| Lanes | `unit`, `unit-legacy-json`, `vet-build`, `race`, `integration`, `integration-race`, `gofmt`, `coverage` and `fuzz`, each with `ci.yml`'s exact command. `-count=1`, `-race`, both 30-second fuzz budgets and the integration suite's own process are kept |
| Not measured yet, with the reason | staticcheck and golangci-lint (they install tools from the network on a miss), supply-chain (reads a live vulnerability database), docker/Compose (an optional lane kept external), Node, browser and advisory lanes (B05, B06), and the long acceptance, chaos, production and release scopes (reported separately, never inside the sub-minute target) |

## Conditions

| Condition | Procedure (unmeasured, before every sample) | Samples |
|---|---|---|
| `cold` | Sources at the pinned commits, and the image present (a pull is measured apart). Build cache, module cache and tool binaries emptied; the module cache is made writable first, because Go makes it read-only. Modules that the checked-in `.goproxy` lacks come from `proxy.golang.org`, as they do in CI after a miss, so a cold sample depends on the network | 3 |
| `warm` | Unchanged source at the pinned commit. Caches are kept from the previous sample, and one unrecorded warm-up primes them. Tests still run: `-count=1` | 10 |
| `small-edit` | Warm caches plus a fresh edit per sample: an inert unexported declaration appended to `internal/s3/cors.go`, different each time. The package recompiles and every test binary depending on it relinks | 10 |

## Freshness

- Every required test runs on every sample: `-count=1` is in every command, and no test result is reused.
- A sample counts only when the lane exits 0. A failing sample aborts the record.
- Changing any frozen item makes a new revision.
- A record is valid for comparison for 30 days, on the reference host, taken under the same revision. The contract digest in the record settles which revision that was.
- The runner refuses to start when CPU pressure (`some`, avg60) is 5 % or more. `bench/b01-measure.sh` waits for it to drop under 2 % before each step, so one lane's load never leaks into the next.

## The runner

`sentinel-bench --contract FILE --lane ID --condition cold|warm|small-edit --root DIR --runtime scoped|podman` behaves as follows:

- It loads the contract and checks the host (CPU model, CPU count, memory), the Podman version, the image digest and that each source holds its pinned commit. Any difference is a refusal that lists every mismatch. Nothing is measured and nothing is written.
- It runs the condition's preparation before each run. The small-edit nonce changes every sample.
- It runs the lane under the contract's allocation unless `--cpus`/`--memory` say otherwise, and records the toolchain the measured runtime actually runs (`go version` through the same wrapper).
- Its record adds `contract {id, revision, blake3, lane, condition, cpu_pressure_avg60, sources, image}` and `toolchain` to the [record format](benchmarking.md#record-format-sentinel-bench1).

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

## Results

Record: [`bench/b01-isolation.jsonl`](../bench/b01-isolation.jsonl), taken 2026-09-28 on the reference host. Every lane record carries contract revision 1, BLAKE3 `b0415e063bb9…` (the committed file), CPU pressure 1.55–1.95 % at its start, and `go1.27.1` as both runtimes report it. The runner was built from `db9e664` plus the uncommitted B01 changes (`git_dirty: true`) that the commit adding this page contains.

**The Part 01 no-op floor, extended with identical isolation** (20 samples each, 2 warm-ups):

| Runtime | Caps | min | median | p95 | max |
|---|---|---|---|---|---|
| direct | none | 0.7 ms | 0.8 ms | 1.3 ms | 1.6 ms |
| scoped | 1 CPU, 256 MiB | 9.3 ms | 11.7 ms | 19.4 ms | 34.2 ms |
| podman | 1 CPU, 256 MiB | 336.5 ms | 354.7 ms | 363.5 ms | 397.6 ms |
| scoped | 10 CPUs, 26 GiB | 9.6 ms | 11.0 ms | 12.7 ms | 13.2 ms |
| podman | 10 CPUs, 26 GiB | 331.4 ms | 361.1 ms | 384.3 ms | 386.5 ms |

**The contract's `unit` lane** (Lockwell `ci.yml` `test` unit step: every non-integration package, `-count=1`), 10 CPUs and 26 GiB:

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
- **Warm unchanged source is about 64–66 s, and a small edit costs no more.** Lockwell's F06 probe found this lane wait-dominated (`internal/consensus` alone takes about 59 s). A cached build cannot shorten tests that `-count=1` runs every time, so the remaining time is the tests themselves. That is where B04 and B07 have to look.
- Cold is about 28–31 s slower than warm: compilation plus the module downloads the checked-in proxy lacks. The cold samples depend on the network, and three samples are only indicative.
- The lane's warm time is the same order as CI's `test` step median of 70 s ([CI baseline](ci-baseline.md)). The sub-minute target cannot be met by the engine alone for this lane.

## B02: the same lane through each executor

The contract's `unit` lane measured through four executors on the reference host, each under the contract's 10 CPUs and 26 GiB, on 2026-09-29. Warm-up runs are excluded. Hosted Blacksmith and Depot runners were **not** measured: there is no account for either, so there is no comparison, and vendor speed-up claims are not Sentinel evidence.

| Executor | What the clock covers | Record |
|---|---|---|
| Direct, scoped (B01) | the test command only, in a systemd scope with the caps | [`b01-isolation.jsonl`](../bench/b01-isolation.jsonl) |
| Podman (B01) | the test command in a container, same caps | same |
| Woodpecker 3.18.1, `woodpecker-cli exec` | spawn to exit of a one-step local pipeline, with its Docker backend on the bench user's rootless Podman socket and `--backend-docker-limit-*` set to the caps. No clone (the bench root is mounted), and caches are the mounted directories | [`b02-woodpecker.jsonl`](../bench/b02-woodpecker.jsonl) |
| GitHub self-hosted runner 2.337.0 | per step and per job from the Actions API (1-second resolution). The run was created by a push, and the job repeats `ci.yml`'s `test` job up to its unit step: checkout from github.com, `setup-go` (tool cache, no remote cache), both SDK checkouts at the pinned commits, `go mod download`. The runner ran as a systemd user service with the caps, on Lockwell's repository, labelled only `sentinel-b02` | [`b02-github-runner.jsonl`](../bench/b02-github-runner.jsonl) |
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

- **Sources.** The GitHub runner checks out from github.com over the network. Woodpecker and the direct runs use the checkout in place. Sentinel's jobs have no network egress and no extra checkouts yet, so its bench source is Lockwell `cbe48fc7` plus the two SDK trees vendored under `sdk-checkouts/`, `.goproxy` completed from a warm module cache of the same `go.sum`, and the pipeline ([`b02-sentinel.yml`](../bench/b02-sentinel.yml)). The test command, image, caps and SDK bytes are the same. The cold samples therefore differ: Sentinel's read modules from the local proxy, while the others fetched those missing from `.goproxy` over the network.
- **Users.** Woodpecker and Sentinel run the step as uid 0 inside a rootless container (the bench user outside). Podman in B01 kept the user's own uid, and the GitHub runner and scoped runs ran directly as the bench user.
- **Clock start.** GitHub's job clock starts at run creation, after GitHub received the push. Sentinel's starts at the intake event, after the push. Woodpecker's has no source step at all.

What the measurements say:

- **The lane is test-bound.** Every executor spends 64–67 s in the same `go test -count=1`, and no engine changes that. The sub-minute target for this lane needs the test time itself to shrink (B07), not only the engine.
- **Engine overhead is about 11 s for both Sentinel and a healthy self-hosted runner.** Sentinel is not faster than the GitHub runner on this lane today: 77.6 s against 75 s of job plus about 2 s of queue. Woodpecker's exec adds 1–3 s over a bare container because it does no source or cache handling.
- **Sentinel's overhead, in order of size:** 4.2 s from intake to dispatch (the controller resolves the pipeline at the pushed revision through Git before creating the run), 3.0 s of cache publication in finalize, 1.8 s of checkout, and 1.0 s of registry manifest check per job. These are B04's first targets.

Found on the way: the repository's HTTPS Git test fixture (`fixtures/git_https.py`) did not pass `Content-Encoding` or `Git-Protocol` to `git http-backend`. A fetch from a populated mirror sends a gzipped request over about 1 KiB, and the server hung up. It now passes both. The Lockwell branch `sentinel-bench/b02` carried only the benchmark workflow. Its runner registration was removed after the samples, and the branch is deleted, while the runs stay in the Actions history.

## Reproducing

1. As root on the reference host, enable lingering for the bench user so it has a systemd user manager: `loginctl enable-linger sentinelbench`.
2. Put git bundles of the three sources in a directory the bench user can read. Build `sentinel-bench` (`cargo build --release -p sentinel-bench`) and copy it, `contracts/` and the two scripts into a kit directory.
3. As the bench user, run `bench/b01-setup.sh ~/b01-scoped BUNDLES` and `bench/b01-setup.sh ~/b01-podman BUNDLES`.
4. Run `bench/b01-measure.sh KIT OUT` detached (it takes about two hours). Copy `OUT` to `bench/b01-isolation.jsonl`.
