# Working on Sentinel

**Rule one: write the most optimized code possible, every time.** Sentinel exists to beat other CI engines on the same hardware, so every change is judged on its cost: no allocation, copy, syscall, lock, or database round trip that the work does not require; hot paths are branch-light and cache-friendly; data structures are chosen for the access pattern; measurements, not guesses, justify anything slower than the obvious fast path. Correctness and bounded resource usage are not traded away for speed, but slow-and-simple is not an acceptable default.

Sentinel is a performance-first, self-hosted Rust CI engine. Read [README.md](README.md), then use [TODO.md](TODO.md) as the execution tracker and [plan.md](plan.md) as the design reference. v0.1 is native `.sentinel.yml` pipelines on Linux workers (Parts 00–15 and the Part 24 re-audit), including Q11–Q13 worker onboarding/host policy and the B11 Blacksmith gate. The Linux microVM implementation landed early; M01–M06/M08 verification belongs to the current release, while runner mode and Windows jobs remain M6 unless separately promoted.

## Workflow

- Pick the task named under **Next task** in `TODO.md` unless told otherwise. Keep task IDs stable.
- Mark a task `[x]` only when code, docs and verification exist. Add a completion-log row with the commit title, linked docs and the actual test/benchmark evidence, then update **Next task**. A decision changes every task and plan section it affects, not only a new paragraph; history stays in the completion log and the benchmark contracts' revision notes.
- Do not invent measurements. Record unavailable hardware or blocked prerequisites as `Blocked by: ...`, and a run that is still going as in progress, never as a result.
- Preserve the boundaries in the backlog: separate server/worker processes, tenant ownership, durable transitions, bounded resource usage. Add crates only when useful.
- Commit with a conventional prefix (`feat:`, `fix:`, `perf:`, `build:`, `docs:`) and a message that describes behavior, not files.
- Pilot work uses only operator-controlled mirrors or forks selected in private runner configuration, never their upstream projects. Public contracts and records use anonymized source and host labels; live repository names, installation IDs, deployment addresses and credentials stay untracked. Benchmarks run the pipelines in `examples/pilots/` on an egress worker under the contract revision in force ([benchmark contracts](docs/benchmark-contracts.md)).

## Where tests run

Maintainers run every test of any size — a single test binary, the full suites, the web browser test and benchmarks — on designated Linux verification hosts, never on a workstation or in WSL. Local work stops at formatting, `cargo check`/lint and `pnpm -C web typecheck`. Host addresses, accounts and keys stay in git-ignored local configuration ([`.env.example`](.env.example)); the details are in [development](docs/development.md#where-tests-run).

| Host class | Role |
|---|---|
| x86_64 with KVM | Default verification, multi-host controller and microVM tests |
| x86_64 without nested KVM | Same-hardware reference benchmarks and rootless-Podman workers |
| arm64 without nested KVM | arm64 rootless-Podman worker tests |

- Run a test on the host class its role needs. A benchmark runs only on the host its contract pins, and its record uses a stable anonymized host label; records from different hosts are never one series.
- Verification hosts may also run production services. Never stop, restart, reconfigure or load them beyond the run: work under `nice -n 19 ionice -c3` with `CARGO_BUILD_JOBS` limited, check `/proc/pressure/cpu` first, and when a host is heavily loaded skip the run and record the verification as pending. Never touch production data or production checkouts.
- Fault injection stays inside Sentinel's own processes, network namespaces and loop devices.
- Take the benchmark lock with `flock -o`, so processes started under it never inherit it. Stop your own processes by PID, never by pattern: `pkill -f` also matches the SSH command's shell and the host's other services.
- Align toolchains through `bench/hosts/align-toolchain.sh` and `bench/hosts/build-podman.sh`. Never install a package that conflicts with Docker CE; the scripts refuse an apt plan that removes a package.

Verify a change with the tests that cover it (the affected test binaries, plus `cargo lint`/`cargo lint-linux`). Run the full suites once per Part of `TODO.md`, when its last task is done, not after every task or change, and keep stress runs short. The test aliases run through [cargo-nextest](https://nexte.st), every test of every binary in parallel.

## Commands

Run from the repository root; aliases live in `.cargo/config.toml`. The test commands run on the verification hosts above, not locally.

| Purpose | Command |
|---|---|
| Portable checks (all OSes) | `cargo fmt-check`, `cargo lint`, `cargo test-cli`, `cargo release-cli` |
| Linux role checks | `cargo lint-linux`, `cargo test-server`, `cargo test-worker`, `cargo test-linux`, `cargo release-linux` |
| Benchmark runner | `cargo bench-noop --runtime direct --warm-state warm`; contract runs `sentinel-bench --contract <file> --lane <id> --condition <c>` |
| Feasibility probes | `cargo probe sqlite --path /tmp/d.sqlite` |
| Web interface | `pnpm -C web install`, `pnpm -C web typecheck`, `pnpm -C web build`; browser test `cargo test -p sentinel-api --test web_browser -- --ignored` (Node, Edge/Chrome/Chromium) |

All aliases pass `--locked`; a dependency change must update and commit `Cargo.lock` (use `cargo update --workspace --offline` for new members). Apply formatting with `cargo fmt --all`.

## Layout

| Path | Purpose |
|---|---|
| `crates/sentinel-core` | Pure contracts: IDs, state machine, failure classes; see [docs/core-contracts.md](docs/core-contracts.md) |
| `crates/sentinel-auth` | Password hashing, opaque secrets, cookie/CSRF policy, TOTP/recovery codes, sealed storage; see [local authentication](docs/local-authentication.md), [API credentials](docs/api-credentials.md), [step-up](docs/step-up.md) |
| `crates/sentinel-link` | Worker link: generated TLS identity, pinned mutual TLS, full-duplex framing, hello/heartbeat, pushed cancel, the controller's dispatch loop (`controller` feature) and the worker's reconnect loop; see [worker link](docs/worker-link.md) |
| `crates/sentinel-github` | GitHub sign-in: bounded HTTPS client, code exchange, verified identity; see [GitHub sign-in](docs/github-sign-in.md) |
| `crates/sentinel-git` | Bounded Git: exact-revision checkout, file-at-revision reads through a blob-less partial clone, one credential and process-group discipline; shared by the worker and the controller's source resolution; see [sources](docs/sources.md), [mirrors](docs/mirrors.md), [generic Git verification](docs/generic-git-verification.md) |
| `crates/sentinel-intake` | Provider-independent run intake: manual, generic hook and polling sources resolved to runs; see [intake](docs/intake.md) |
| `crates/sentinel-store` | SQLite metadata store, single durable writer; see [docs/storage.md](docs/storage.md), [retention](docs/retention.md) |
| `crates/sentinel-s3` | Optional external S3 client: Signature V4, multipart with resume, range reads, abort cleanup, the endpoint compatibility matrix; see [docs/s3.md](docs/s3.md) |
| `crates/sentinel-mail` | Durable email delivery: the outbox lane and a bounded Resend HTTPS client |
| `crates/sentinel-checks` | Durable check delivery: the outbox lane and the GitHub Checks publisher; see [checks](docs/checks.md) |
| `crates/sentinel-api` | The controller's HTTP API; see [API](docs/api.md) |
| `crates/sentinel-worker` | Linux executor: fresh workspaces, exact-revision checkout, rootless Podman containers and Firecracker microVMs, attempt lifecycle, log redaction and spool; see [executor](docs/executor.md), [logs](docs/logs.md) |
| `crates/sentinel-agent` | Static Linux guest agent: boots the microVM, executes steps over vsock and streams their output |
| `crates/sentinel-protocol` | Errors, idempotency, cursors, limits, negotiation and guest-agent framing; see [docs/protocol.md](docs/protocol.md) |
| `crates/sentinel-pipeline` | `.sentinel.yml` loader, schema and compiler; see [docs/pipeline-schema.md](docs/pipeline-schema.md) |
| `crates/sentinel-cache` | Worker-local cache metadata: scope paths, sealed-generation manifests, explainable hit/miss reasons; see [docs/cache.md](docs/cache.md) |
| `crates/sentinel` | CLI (`pipeline`, `api` client, host-local `admin`) plus Linux `server`/`worker` roles behind features |
| `crates/sentinel-bench` | Benchmark runner and contract checks; see [docs/benchmarking.md](docs/benchmarking.md), [benchmark contracts](docs/benchmark-contracts.md) |
| `crates/sentinel-probes` | SQLite/clone probes; see [docs/feasibility-probes.md](docs/feasibility-probes.md) |
| `web/` | The web interface, `sentinel-web` (TanStack Start, React, TypeScript, Tailwind CSS v4; pnpm), its own Node process with server rendering: pages, live event streams, the proxy to the API, its tests and benchmark; see [web interface](docs/web-ui.md) |
| `bench/` | Committed machine-readable benchmark records, frozen contracts (`bench/contracts/`), harness scripts and host setup (`bench/hosts/`) |
| `fixtures/` | Valid and invalid pipeline fixtures exercised by tests |
| `docs/` | Contracts and guides: [development](docs/development.md), [configuration](docs/configuration.md), [runtime foundations](docs/runtime-foundation.md) |
| `examples/` | Sanitized configuration files and the live pilot pipelines (`examples/pilots/`, run on an egress worker; also the Part 14 bench lanes) |
| `.local/`, `data/`, `target/` | Ignored local state; never commit credentials or generated data |

## Conventions

- Rust 1.97, edition 2024, `unsafe_op_in_unsafe_fn = deny`; every `unsafe` block carries a `// SAFETY:` comment.
- Durations are monotonic `Instant` measurements in nanoseconds; wall-clock timestamps are provenance only. Unmeasured fields are absent, never zero.
- Diagnostics must not echo configuration or parser payloads that could contain credentials. Public contracts and records use stable anonymized host labels; addresses, account names, credentials and keys stay in git-ignored files.
- Tests cover behavior and failure paths; do not add tests that merely mirror the implementation.
- Sandboxes follow the host ([plan 16.8](plan.md#168-microvm-execution-on-kvm-hosts)): rootless Podman where there is no KVM; on x86_64 KVM hosts, Firecracker for Linux guests and Cloud Hypervisor for Windows guests. No QEMU. The Firecracker executor is in development; Cloud Hypervisor and Windows guests remain planned. Jobs have no network unless the worker's operator sets `job_network = "egress"`.
- One GitHub App; a feature that needs more permissions (runner mode, guided migration) asks for them only when a tenant turns it on.
- Versioned contracts (pipeline schema, run spec format, migrations, error/explain schemas, cursors, worker protocol) change only under [docs/compatibility.md](docs/compatibility.md).
- Keep commits and code free of AI attribution and co-author trailers. If an AI agent wrote the change, disclose it in the pull-request description instead, naming the model and harness.
