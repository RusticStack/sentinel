# Release notes: v0.1 (draft)

**Status: draft, not published.** This page is prepared ahead of the release and is published only together with the final release-qualification record. Nothing here is a release claim. Until the release gates close, [Open blockers](#open-blockers) is the part of this page that matters most. The numbers in [Measured performance](#measured-performance) are copied from committed records in [`bench/`](../bench/) and carry their sample counts; when a record changes, this page changes with it.

## What v0.1 is

A self-hosted, Rust CI engine with a controller (`sentinel server`), workers (`sentinel worker`) and a command-line client (`sentinel`). v0.1 supports **native pipelines** (`.sentinel.yml`) on **Linux workers running rootless Podman**, on x86_64 and arm64. GitHub Actions runner mode, microVM execution and Windows workers are not part of the v0.1 support set; their real state is listed [below](#support-matrix).

## Support matrix

| Area | State | Evidence and limits |
|---|---|---|
| Native pipelines, Linux, rootless Podman worker | Supported target. Verified on the x86_64 and arm64 Linux verification hosts for the pieces named in [releasing](releasing.md#verification-record) (packages, units, container, local operation) | End-to-end release qualification is not yet recorded; see [qualification](qualification.md) and [Open blockers](#open-blockers) |
| Controller and worker packages | x86_64 and arm64 Linux archives with a digest manifest, license inventory and manifest verifier | [releasing](releasing.md) |
| Deployment | systemd units, container and Podman Quadlet examples, nginx and Caddy configurations, fully local operation without network | [deployment](deployment.md) |
| Git sources | GitHub App ingress and checks, and a generic Git remote through a hook | [sources](sources.md), [generic Git verification](generic-git-verification.md) |
| Caches, secrets, tenants, OAuth CLI and MCP | Implemented; revalidation continues in the correctness pass | Per-area tests listed in [qualification](qualification.md#stages) |
| Linux microVMs (Firecracker) | **Not a v0.1 support claim.** The executor and its gated tests exist, the x86_64 worker package carries the pinned Firecracker, guest kernel and agent, and `worker --check` reports each missing piece. Boot-only measurements exist ([`bench/m02-boot.jsonl`](../bench/m02-boot.jsonl)). No run closes the microVM executor's end-to-end gate, and per-attempt snapshot restore and microVM network policy are not verified | Needs a KVM host; hosts without KVM keep rootless Podman |
| GitHub Actions runner mode | **Not implemented.** There is no runner provisioning code | Planned after v0.1 |
| Windows | The CLI is packaged for Windows. **No Windows worker or Windows job execution exists**; a job that requires `runs_on.os: windows` is refused with an explanation by placement | Planned after v0.1 |
| Hostile fork pull requests | Not supported. A fork pull request is ignored. Rootless containers alone are not a sufficient boundary | Needs the microVM pool |
| Web interface | Being replaced; not described here | |

## Measured performance

All durations are for the three pilot workloads of the frozen `pilots-ci` contract, revision 4, run on the reference host the contract pins, with Sentinel and the GitHub self-hosted baseline pinned to separate CPU complexes. Sources: [`bench/p14-pilot-cli.jsonl`](../bench/p14-pilot-cli.jsonl), [`bench/p14-pilot-ripgrep.jsonl`](../bench/p14-pilot-ripgrep.jsonl), [`bench/p14-pilot-gson.jsonl`](../bench/p14-pilot-gson.jsonl) and [`bench/b01a-github-cli.jsonl`](../bench/b01a-github-cli.jsonl), [`bench/b01a-github-ripgrep.jsonl`](../bench/b01a-github-ripgrep.jsonl), [`bench/b01a-github-gson.jsonl`](../bench/b01a-github-gson.jsonl). Warm-up samples are excluded; every counted sample passed every required job. The contract and its freshness rules are in [pilot workloads](pilot-repositories.md#check-contracts-and-benchmarks) and [benchmark contracts](benchmark-contracts.md).

**Sentinel, event intake to run finished, seconds** (`intake_to_finished_ns`). The p95 is the nearest-rank value; with fewer than 20 samples it equals the maximum, so it is not a release-grade tail.

| Lane | Condition | Samples | Min | Median | p95 (nearest-rank) |
|---|---|---|---|---|---|
| cli | cold | 3 | 99.78 | 99.84 | 102.32 |
| cli | warm | 10 | 63.67 | 63.95 | 64.08 |
| cli | small edit | 5 | 63.95 | 64.18 | 64.22 |
| ripgrep | cold | 3 | 23.84 | 24.10 | 24.87 |
| ripgrep | warm | 10 | 21.24 | 21.32 | 21.39 |
| ripgrep | small edit | 5 | 21.39 | 21.54 | 22.57 |
| gson | cold | 3 | 69.64 | 69.91 | 71.28 |
| gson | warm | 10 | 42.67 | 42.88 | 44.02 |
| gson | small edit | 5 | 42.83 | 42.90 | 44.05 |

Cold samples include network dependency downloads.

**GitHub Actions self-hosted baseline on the same host, seconds** (push to last job completed, five counted runs per lane):

| Lane | Min | Median | Max |
|---|---|---|---|
| cli | 103 | 105 | 109 |
| ripgrep | 28 | 28 | 30 |
| gson | 80 | 81 | 88 |

The Sentinel and baseline columns are measured on different clocks (event intake to run finished, and push to last job completed). They are listed side by side for context and are **not** a ratio: no speedup is claimed from them. A cached-test variant of the cli baseline ([`bench/b01a-github-cli-cached-tests.jsonl`](../bench/b01a-github-cli-cached-tests.jsonl)) is a different workload condition and is not mixed into the table.

## Claims this release does not make

- **No sub-minute claim.** The absolute target (warm required-check p95 below 60 s against a baseline of at least 300 s on the same hardware) is **unmet**: the largest recorded baselines are 109 s (cli), 88 s (gson) and 30 s (ripgrep), all below 300 s, and the cli warm p95 above is 64.08 s. The threshold and workloads are not changed to fit.
- **No 2x claim.** The primary relative target (trigger-to-required-check p95 at most half of Blacksmith's for the same checks and conditions) has no comparison data. No Blacksmith execution has been measured; the self-hosted GitHub baseline above is not Blacksmith evidence.
- No claim for runner mode, microVM or Windows performance; none has been measured as a supported path.
- The one-run Blacksmith startup probe in the plan is a comparison reference only.

## Open blockers

| Gate | State | What is missing |
|---|---|---|
| B08 absolute target | Unmet | A representative lane whose same-hardware baseline reaches 300 s, and a warm p95 below 60 s on it |
| B11 Blacksmith comparison | Blocked | Blacksmith benchmark access; then 100 paired release samples per lane and condition, raw distributions and the one-sided 95 % bound on the paired log-duration ratio below 0.50 |
| B09 reliability and load combinations | Open | A real multi-worker run through enrollment and host policy (Q13); no committed result record |
| B10 shadow parity and switch | Open | Committed anonymized parity evidence and the documented rollback |
| Q11, Q12, Q13 host management | Open | UI-generated enrollment, authoritative host caps and placement, and the real-fleet verification |
| Part 24 correctness pass | In progress | Remaining findings; closure also needs the items above |
| V05 release qualification | Harness drafted | A recorded PASS from [qualification](qualification.md) on the final commit and packages |
| M-series (microVMs) | Open | M01 to M06 and M08 are required before any verified Linux microVM claim; M07 (Windows guests) and M09 (hostile fork pool) are later |
| Runner mode (AR-series) and Windows workers (N-series) | Not started for v0.1 | Out of the v0.1 support set |

v0.1 is tagged only when the required correctness and operational gates are met. The sub-minute and 2x statements are never checked off through a documentation exception.

## Upgrading and compatibility

A new deployment starts at the current schema. An upgrade of an existing deployment follows [upgrades](upgrades.md); rollback to an older release is, from the current schema, only possible from the pre-migration copy or a backup. Versioned contracts and their change history are in [compatibility](compatibility.md).
