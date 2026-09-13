# Lockwell -> Sentinel migration specification

Status: requirements and conversion design, **not an executable Sentinel pipeline**. Sentinel is currently a planning repository. Lockwell workflows and tests have not been changed by this review.

Repository: `RusticStack/lockwell` (the requested “lovkwell”). Reviewed main on 2026-09-13; observed HEAD `0c2ec406cc79e8af89856401863785eb210d7e71`. Recheck source revisions before implementation because workflows were read from moving main.

## Objective

Adapt Lockwell CI to Sentinel's purpose-built performance model, preserving the assertions/evidence of each migrated lane while reducing waiting, repeated work, and contention. Port orchestration and provider-specific contract tests; keep Go tests, SDK conformance, and acceptance validators repository-owned. Supporting Lockwell does not justify fundamentally changing Sentinel or reproducing every Actions feature.

**Scope correction:** the earlier demand for all six workflows, VM pools, Docker/Compose compatibility, and publishing as Sentinel v1 release gates is withdrawn. Lockwell is a demanding measurement/adaptation case. Adapt tests to existing Sentinel execution primitives; lanes needing unsupported capabilities may stay external. Complete replacement remains a repository migration goal, not a requirement to reshape the engine. The inventory below records current workload needs and possible translations, not committed core features.

## Observed workflow inventory

| Source workflow | Current scopes | Sentinel conversion |
|---|---|---|
| `ci.yml` | Push main / PR main and acceptance branch; 12 jobs: docs, test, test-race, lint, integration, docker, coverage, supply-chain, fuzz, playwright, s3compat, scripts | Named `ci` DAG, per-lane resources/caches/reports, preserve advisory status and required checks |
| `acceptance-gate.yml` | PR/manual; Saturday 03:17 UTC long lane; 60-minute normal / 210-minute scheduled job limit | Named `acceptance`, current head + full history, real owned cluster, generated configuration/signing material, required evidence, always cleanup, 14-day evidence retention |
| `acceptance-focus.yml` | Manual scenario/SDK/invariant selection, 45-minute limit | Typed validated inputs on `focus`; selected hooks and prerequisites, real cluster, row-level evidence; never a full acceptance pass |
| `cluster-chaos.yml` | PR deterministic consensus; manual transport/deterministic switches; daily 03:17 UTC full chaos | Named `chaos` with 15-minute deterministic/transport and 120-minute Docker lanes; exact source provenance, fault capabilities, teardown, required evidence |
| `production-test.yml` | Manual `skip_huge`/`keep_stack`, 120-minute limit | Named `production`, full client matrix/large disk profile, partial/full labels, bounded debug retention and mandatory eventual cleanup |
| `release.yml` | `v*` tags; validate -> Docker -> GitHub release | Named `release`, manifest/tag checks, pinned source, multi-arch build, provenance/SBOM, immutable publication/readback and release notes |

### Required test coverage

- `test`: `go vet ./...`; `go test -count=1` over `go list ./...` excluding `/tests/integration`; six wire-sensitive packages under `GOEXPERIMENT=nojsonv2`; `go build ./cmd/...`; CLI/daemon help.
- `test-race`: same non-integration package set with `-count=1 -race`. Keep the race detector mandatory.
- `integration`: complete `./tests/integration/...` in an isolated process, both normal and `-race`, each with `-count=1`. The workflow explicitly documents prior timeouts when this real-daemon suite competed with all other packages.
- `lint`: gofmt check that fails without modifying files, `make staticcheck`, `make lint`.
- `coverage`: advisory non-harness coverage output plus mandatory `make coverage` production floor; current Makefile default is 60%, ratchet-only. Preserve scope/threshold rather than substituting a different report.
- `supply-chain`: `make supply-chain` and required output directory.
- `fuzz`: `FuzzParseCredential` and `FuzzParseRange`, each 30 seconds; preserve corpus/failure artifacts and fuzz time budget.
- Docker build/start and Compose lifecycle; S3 compatibility CLI against a real seeded daemon; documentation lint; test-file generator and integration script; browser smoke.
- Current Playwright command and script integration command contain `|| true`; port as visible **advisory** outcomes rather than silently representing failures as passing tests. Promoting them to required gates is a separate Lockwell decision.
- Full acceptance/production/chaos validators must still reject missing, stale, skipped, or unavailable required evidence. Focus, deterministic-only, transport-only, and `skip_huge` are scoped evidence, not substitutes.

## Toolchain and source inputs

- Checked-in Go requirement and setup are **1.27.0**, with `GOTOOLCHAIN=local`; verify toolchain availability in image provisioning, never silently substitute a different version.
- Docs/browser normal CI currently uses Node 20; acceptance/production use Node 22; Java conformance uses JDK 25. Repository Maven setup/contract pins 3.9.16. Preserve per-lane versions initially and record their actual resolved binaries.
- Makefile pins staticcheck 0.8.1, golangci-lint 2.12.2, govulncheck 1.3.0, cyclonedx-gomod 1.10.0. Build tools using the intended Go version so Makefile checks do not reinstall them each run.
- Images also need Bash, Git, make, C toolchain for race/CGO where needed, Python, OpenSSL, curl, and lane-specific browser/Docker tools. Validate capabilities before placement.
- Go SDK is pinned via `go.mod`/`go.sum` and a checked-in `.goproxy`; preserve `GOPROXY=file://<workspace>/.goproxy,https://proxy.golang.org,direct`.
- Node/Java SDKs are separate authorized checkouts at `sdk-checkouts/lockwell-sdk-node` and `sdk-checkouts/lockwell-sdk-java`, provided by `LOCKWELL_SDK_NODE_DIR` / `LOCKWELL_SDK_JAVA_DIR`. Missing repositories fail closed. The SDK repos' own CI/publish workflows are separate migrations, not inspected here.
- Resolve SDK refs once and persist every commit in a source manifest. Existing Actions checkouts do not pin explicit SDK refs; Sentinel should freeze the resolved refs for reproducible reruns. GitHub App read grants can replace the broad checkout token where installation access permits.
- Acceptance and rolling-upgrade scenarios need full history and the reviewed compatibility baseline commit. A shallow checkout is not an equivalent optimization.
- PR acceptance/chaos explicitly test the head SHA; ordinary Actions checkout may test a merge ref. Choose and document each lane's intended checkout policy during parity testing; do not compare different SHAs and call results equivalent.

## Conversion contract

| Actions mechanism | Sentinel-native replacement |
|---|---|
| Checkout/setup actions | Compiled checkout manifest + digest-pinned prebuilt toolchain environment |
| `github.*`, `RUNNER_TEMP`, `GITHUB_WORKSPACE` | Typed Sentinel source/event/run/workspace/temp context |
| `GITHUB_OUTPUT` | Bounded declared non-secret step/job outputs; private key paths remain job-local |
| `vars.*` routing | Operator-granted pool/resource profiles; tenant-scoped locks for scarce environments |
| `workflow_dispatch` and input expressions | Typed manual dispatch with validated lists/enums/booleans |
| Cron schedule | Durable UTC scheduled occurrence and overlap/recovery policy |
| `if: always()` and shell traps | Explicit finalizers plus independent worker-owned reaper |
| Upload/download artifact actions | Native artifact policy, stable evidence IDs, checksums, retention, missing-file failure semantics |
| `GITHUB_TOKEN` | Explicit scoped source/publish credentials; no assumed Actions-issued token |
| Buildx/login/metadata/build-push actions | Repository scripts invoking pinned build/registry tooling inside isolated environment |
| GitHub error annotations | Structured diagnostics and Checks annotations with source/evidence references |

Create `.sentinel.yml` for supported lanes and small repository `scripts/ci/` entry points. Split/merge old workflow boundaries according to real dependencies and feedback needs; six named pipelines are one possible future layout, not required syntax. Replace `LOCKWELL_GITHUB_ACTIONS_CHAOS` and provider-specific execution-scope detection with accurate execution provenance in repository scripts; merely spoofing GitHub variables is not authorization. Keep unsupported integrations external rather than building an Actions shim or Lockwell-specific executor.

Port `docs/runner_ci_contract_test.go` and related toolchain/release/automation/production contract tests alongside CI docs. Many currently assert exact Actions filenames, routing expressions, setup steps, and environment markers. New tests should validate Sentinel's compiled plan/declared invariant plus harness behavior, retaining coverage, isolation, toolchain, evidence, and cleanup assertions. Do not delete those assertions to obtain green tests. Search the whole repository for provider-specific assumptions during implementation, including `CI.md`, `RELEASE.md`, and scripts.

## Execution profiles and cleanup

1. **General Go/docs:** rootless job containers, warm Go/npm caches, hard resource budgets.
2. **Integration:** reserved CPU/memory and process isolation; budget Go `-p`, `-parallel`, and `GOMAXPROCS` to assigned cores. Preserve all packages/cases.
3. **Cluster/acceptance:** first evaluate running the real daemons as isolated job processes or using an explicitly provisioned test target through repository scripts. Reserve resources for nodes/clients/harnesses, not only the driver. Exact Docker/Compose semantics remain an optional compatibility lane; a VM environment may be provisioned externally, but Sentinel does not acquire a VM manager for this repo. The observed chaos template caps each node at 2 CPUs/2 GiB; measure total peak. Fault scenarios that need unavailable isolation/capabilities remain unmigrated, not silently simplified.
4. **Production-large:** separate capacity/queue profile and measured disk reservation for simultaneous copies, multipart data, container layers, logs, and cleanup headroom. A 15 GiB test needs more than 15 GiB free. Never replace streaming/durability disk tests with tmpfs to win benchmarks.
5. **Release:** repository commands on authorized compatible amd64/arm64 workers, scoped registry access, separate publication permission. Native capacity/emulation is an explicit environment requirement for that lane; Sentinel need not implement a release service or provision QEMU. Keep the lane external if required capabilities are unavailable.

The shared-host workflows use fixed port blocks 9100/9200/9300 and 19000+; acceptance/focus share a serialized block around 19010–19042. Adapt scripts to job-private networking and allocated endpoints where equivalent, rather than preserve global port constraints in the core. Explicit resource leases remain necessary for genuinely shared external targets. Although chaos comments say host publishing is disabled, the inspected script still publishes a webhook-receiver loopback port: inventory generated Compose, not comments alone.

Every stack/container/network/volume/temp directory has run/attempt ownership. Finalizers collect evidence and remove only owned resources; a worker reaper handles cancel/crash cases. No fleet-wide `docker prune`. `keep_stack` becomes an explicitly permitted expiring debug lease within the same tenant/isolated environment, charged to reserved capacity, with eventual forced teardown and no full-gate claim until required cleanup receipts exist.

Prewarming retains immutable tool/image layers, not previous test databases, cluster credentials, or writable guest state. Cache transfer and compression cannot starve cluster timers/control traffic. Network/disk fault injection cannot reach Sentinel control links or another tenant's jobs.

## Evidence and AI experience

- Parse Go JSON into package/test/subtest results, race/panic snippets, duration, and source links. Capture logs without changing the command's exit status (including pipefail when teeing).
- Repository adapters translate acceptance/production JSON/JSONL into Sentinel's report schema. Index scenario, SDK language, invariant, source SHA, dependency SHAs, environment, scope, and cleanup status. No Lockwell-specific report parser in the core.
- Failure view points to the failed row and nearby evidence, not thousands of passing Go tests. Attach log cursors, artifact paths/digests, and provenance.
- Suggested focused rerun includes failing scenario prerequisites. Scenarios such as backup/restore depend on prior topology changes; do not indiscriminately parallelize or execute them out of order.
- Acceptance's generated signing seed, TLS/private cluster config, and credentials are job-local secret material. Upload only intended redacted evidence; never recursively publish a private config tree. Preserve source-bound attestation validation and explicit missing-artifact failures.
- Focused reruns accelerate debugging; after a fix the required complete acceptance gate still runs on the new candidate. Prior evidence from another SHA/SDK/environment cannot satisfy it.

## Release conversion

Preserve tag/package version match, changelog extraction, tagged commit binding, image version metadata, provenance/SBOM, publication checks, binary/daemon readback, and immutable GitHub Release creation after image gates.

Build native architecture images independently and assemble the manifest only after both succeed. Retain the existing release cache policy (no persistent release layer cache) until a reviewed Lockwell change authorizes a reproducible alternative; dependency/tool prewarming alone must not undermine that policy. Non-release image lanes can benchmark safe layer caching separately.

Sentinel gets no automatic `GITHUB_TOKEN`. Provision an explicitly authorized GHCR credential using a currently supported authentication method, plus repository-scoped contents-write credentials for creating Releases; verify exact provider support at implementation. Do not assume every GitHub App token can publish packages. PR code never receives publishing credentials. Registry existence/readback failures must distinguish unauthorized/network errors from missing images.

## Performance and cutover gates

Measure on identical machines and source/SDK/tool/image revisions: cold run, warm unchanged source (tests still execute), and warm small edit. Preserve `-count=1`, race detection, two 30-second fuzz budgets, scenario coverage, deadlines, data sizes, and cleanup.

Optimization order:

1. Persistent worker connection; warmed image/toolchain/Go module/build/npm/Maven/browser caches scoped by tenant/repo/toolchain/arch/trust. Go normal/race/coverage/experiment caches must not collide incorrectly; never use cached **test results** to skip required execution.
2. Remove repeated tool installation from jobs through versioned images. Prefetch SDK/Git objects, keep full history local, record exact refs.
3. `ci.yml` serializes many unrelated lanes behind `test`. After parity, remove only dependencies that represent no data/policy requirement; keep release and stateful acceptance dependencies. Reserve isolated resources for integration/cluster work.
4. Build once and pass checksummed exact-SHA artifacts to compatible smoke/S3/browser jobs where build flags/image/architecture match. Never reuse normal binaries as race evidence or current binaries as an old-version baseline.
5. Prebuild pinned sidecar dependency images: current production clients install boto3/JS dependencies at startup and some use `latest`. Record/pin versions through a reviewed Lockwell change, so speed does not hide changed client coverage.
6. Prefer locality over transferring huge test data; generate run-owned datasets on target disk. Index small reports instead of sending full logs to agents.

Primary ambition is now **under one minute for representative warm PR required feedback on the same hardware previously taking five minutes or more**, not the earlier 25% reduction goal. See [performance research](performance-research.md) for observed 8m38s run timings, cache strategy, a 55-second budget, and experiments needed to make this credible. Keep required-check scope explicit; no dropped assertions or silently cached `-count=1` tests. Report long production/chaos scopes separately without presenting them as completed under a minute. VM/cluster readiness is measured only when such an external/optional environment is actually used.

Cutover checklist:

- Per-workflow parity matrix lists all jobs/triggers/inputs/checks/permissions/artifacts/exit policies and converted command contracts.
- Each migrated lane exercises its full declared checks and evidence under Sentinel. Inventory unsupported lanes explicitly; they keep their existing required checks/executor. Sentinel release does not wait for all of Lockwell's production, chaos, and publishing features.
- Perform registry/release parity in a designated test namespace before any real publish; real release authorization remains the existing repository policy.
- Verify cancel/restart cleanup, parallel port safety, missing SDK/artifact failure, tenant isolation, and bounded AI diagnostics on real failure fixtures.
- Shadow old/new CI with distinct check names, same inputs, separate data/ports, and sufficient capacity to avoid contaminating timings. Publish results before changing required checks.
- Update Lockwell contract tests/docs and native pipelines together; switch required checks per adapted lane after parity, then disable corresponding Actions triggers. Full repository migration eventually accounts for every old scope through equivalent Sentinel methods or explicitly reviewed scope changes; no silent coverage loss and no obligation to retain the old six-workflow structure.

## Reviewed sources

All from [RusticStack/lockwell](https://github.com/RusticStack/lockwell): `.github/workflows/{ci,acceptance-gate,acceptance-focus,cluster-chaos,production-test,release}.yml`, `CI.md`, `Makefile`, `go.mod`, `docs/runner_ci_contract_test.go` (reviewed relevant assertions), `scripts/acceptance-gate.sh`, `scripts/cluster-chaos-docker.sh` (reviewed execution/resource/cleanup sections), and `deploy/compose/docker-compose.production-test.yml`.

Some workflow/CI comments still describe Postgres while the inspected production Compose and current Go module indicate embedded Badger storage. Use executable configuration and tests as the migration source of truth, and reconcile stale prose during conversion. This was a CI design review, not a run of Lockwell's tests or an audit of every source file.
