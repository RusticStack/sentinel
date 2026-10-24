# Pilot workloads

Sentinel's CI contracts, benchmarks and parity checks use three open-source workload families: GitHub CLI (`cli/cli`) for Go, ripgrep (`BurntSushi/ripgrep`) for Rust and gson (`google/gson`) for Java/Maven. Maintainer-selected mirrors or forks supply the exact revisions and Sentinel pipeline files. Their repository names, namespaces, installation IDs and deployment details stay in private runner configuration; the source labels in public contracts and records are anonymized.

The committed pipelines in [`examples/pilots/`](../examples/pilots/) describe the measured Linux lanes. They are workload definitions, not instructions to modify the upstream projects. Changes required for a pilot belong only in an operator-controlled mirror or fork.

## Workflow inventory

The workflow inventory is the parity reference, not a list of engine features to build. Each benchmark contract pins the revision whose workflows were read.

### cli (Go)

| Workflow | Scope | Sentinel conversion |
|---|---|---|
| `go.yml` `build` | `go mod download`, `go test -race -tags=integration ./...`, `go build ./cmd/gh`, and on Linux `go build -tags=ghdebug ./cmd/gh`; Linux, Windows and macOS rows | The Linux row is the measured `build-linux` lane; Windows requires a Windows worker; macOS remains external |
| `go.yml` `integration-tests` | Attestation command tests with `GH_TOKEN` | External until a scoped token can be delivered as a secret |
| `lint.yml` | golangci-lint, `go mod tidy` check and license notices | A `ci` job with the linter pinned in the image |
| `govulncheck.yml` | Scheduled vulnerability check | External until durable schedules exist |
| `acceptance.yml` | Acceptance tests against live GitHub with an App token | External: requires repository secrets and a live service |
| `codeql.yml` | CodeQL hosted analysis | External |
| Release, triage and repository-automation workflows | Repository maintenance rather than CI checks | External |

### ripgrep (Rust)

| Workflow | Scope | Sentinel conversion |
|---|---|---|
| `ci.yml` `test` | Native Linux toolchains, cross/QEMU targets, macOS and Windows; workspace builds and tests with the declared feature sets | Native Linux builds become `ci` jobs, one image per toolchain; emulation and unsupported operating systems remain external |
| `ci.yml` `wasm`, `rustfmt`, `docs`, `fuzz_testing` | wasm build, formatting, documentation and fuzz-target compilation | Separate `ci` jobs with tools pinned in their images |
| `release.yml` | Tagged release builds | External; pilots do not publish releases |

### gson (Java/Maven)

| Workflow | Scope | Sentinel conversion |
|---|---|---|
| `build.yml` `build` | `mvn verify javadoc:jar` across the declared JDK matrix | One job per JDK image, with the Maven local repository as a scoped cache |
| `build.yml` `build-gson-subset`, `native-image-test`, `verify-reproducible-build` | Subset, GraalVM native-image and reproducibility checks | Separate `ci` jobs where their tools run in a pinned image |
| Android and API compatibility workflows | Compatibility checks | `ci` jobs when containerized; otherwise external |
| OSS-Fuzz, CodeQL and Scorecard workflows | Hosted-service integrations | External |

## Conversion contract

| Actions mechanism | Sentinel-native replacement |
|---|---|
| `actions/checkout` | Compiled checkout manifest at the pinned revision ([sources](sources.md)) |
| `setup-go`, `setup-java`, `dtolnay/rust-toolchain` | A digest-pinned toolchain image; record the selected version and never silently substitute it |
| Dependency and compiler caches | Sentinel cache classes per [recipes](recipes.md), scoped by tenant, repository, trust and toolchain |
| `strategy.matrix` | One declared job per cell until bounded matrices exist |
| `$GITHUB_OUTPUT`, `$GITHUB_ENV`, `$GITHUB_PATH` | Typed context and declared environment; outputs only when output contracts are implemented |
| `schedule` | Durable schedules; scheduled scopes remain external until then |
| `permissions:`, `GITHUB_TOKEN` | Scoped source credentials with no ambient or publishing token |

Unsupported requirements remain external in the parity matrix rather than being emulated. Pilot needs must be met through images, commands and general contracts, never pilot-specific engine behavior.

## Check contracts and benchmarks

[`bench/contracts/pilots-ci.json`](../bench/contracts/pilots-ci.json) fixes one Linux lane per workload: cli's Ubuntu `build` row, ripgrep's stable `test` row and gson's JDK 17, 21 and 25 `build` rows. It also pins image digests, resource allocation, source revisions, freshness rules and the `cold`, `warm` and `small-edit` procedures. The harness is [`bench/p14-pilot.sh`](../bench/p14-pilot.sh).

The public contract is an anonymized publication snapshot. Its source URLs and host labels are not live runner configuration, and sanitizing its bytes means its digest is not the digest recorded by historical samples. To reproduce a lane, create a private contract with equivalent inputs and the actual mirror URLs and host configuration; do not compare its records with a different contract revision or digest. The harness reads `SENTINEL_PILOT_CLI_URL`, `SENTINEL_PILOT_RIPGREP_URL` and `SENTINEL_PILOT_GSON_URL`; the GitHub baseline collector reads the corresponding `SENTINEL_PILOT_*_REPO` values as `owner/repository`.

Every required test runs on every sample. The cli lane sets `GOFLAGS=-count=1`; Cargo and Maven tests always execute. A sample counts only when every declared job passes. Cold samples include network dependency downloads and must be interpreted with that condition.

The ≥300-second same-hardware B08 baseline target remains a target, not an assumed result. Revision-4 records have no qualifying lane, so B08 is unmet; do not change the workload to fit it. B11 separately requires trigger-to-required-check p95 at most half of actual Blacksmith's p95 under its [paired contract](benchmark-contracts.md#b11-the-2-blacksmith-gate). GitHub self-hosted baselines and shadow observations are not Blacksmith evidence.

## Performance and parity gates

Measure cold, warm unchanged-source and warm small-edit conditions on identical hardware and source/tool/image revisions. Preserve every race job, CPU target, JDK cell and test filter in converted lanes.

Optimize persistent worker connections and warm caches first, then repeated tool installation, then false dependency edges. Shard only with equivalent assertions and the same total resource budget.

Before cutover, each operator should maintain a parity matrix covering every job, trigger, matrix cell, check name, permission, artifact and exit policy. Run converted lanes in shadow with distinct check names and independent data and resources. Verify cancellation and restart cleanup, missing-artifact failures, tenant isolation and bounded diagnostics. Required checks move only after parity is established; rollback restores the previous workflow and required-check configuration.
