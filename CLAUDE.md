# Working on Sentinel

Sentinel is a performance-first, self-hosted Rust CI engine. [TODO.md](TODO.md) is the tracker (work in waves), [plan.md](plan.md) the design reference, `docs/` the contracts. Read a doc only when the task touches it.

**Rule one: write the most optimized code possible.** No allocation, copy, syscall, lock or database round trip the work does not require; data structures fit the access pattern; measurements, not guesses, justify anything slower than the obvious fast path. Correctness and bounded resource usage are never traded for speed.

## Workflow

- Implement the wave named under **Next wave** in `TODO.md`, item by item. Stop and say so when a wave's **Needs** is missing. Keep task IDs stable.
- A task is done only when code, docs and verification exist. Never invent a measurement; a blocked item says `Blocked by: <prerequisite>`, a run still going is "in progress".
- Preserve the boundaries: separate server and worker processes, tenant ownership, durable transitions, bounded resource usage.
- Commits: conventional prefix (`feat:`, `fix:`, `perf:`, `build:`, `docs:`, `test:`), message describes behavior. Stage only the files you changed. No AI attribution or co-author trailers; disclose AI authorship in the PR description.
- Pilot work uses operator-controlled forks only. Public records use anonymized host and source labels; addresses, installation IDs and credentials stay untracked.
- Versioned contracts (pipeline schema, run spec, migrations, error and explain schemas, cursors, worker protocol) change only under [compatibility](docs/compatibility.md).
- After renaming a heading or moving a doc, run `scripts/check-doc-links.sh`. Headings describe content, not task IDs.

## Where tests run

Every test, of any size, runs on a Linux verification host, never on a workstation or in WSL. Local work stops at `cargo fmt-check`, `cargo lint`/`cargo check` and `pnpm -C web typecheck`, one local build at a time. Host details are in git-ignored local configuration ([`.env.example`](.env.example), [development](docs/development.md#where-tests-run)).

| Host | Role |
|---|---|
| `kvm-host` (x86_64, KVM) | default verification, microVM tests, multi-host controller, `pilots-ci` benchmarks |
| `reference-host` (x86_64, no KVM) | reference benchmarks, rootless-Podman workers |
| `arm64-host` (arm64, no KVM) | arm64 rootless-Podman worker tests |

- The hosts also run production services: never stop, restart or reconfigure them, never touch production data or `/srv/sentinel`. Use a disposable checkout under `/var/tmp`, `nice -n 19 ionice -c3`, a bounded `CARGO_BUILD_JOBS`, check `/proc/pressure/cpu` first and skip (record as pending) when the host is loaded. Long runs go detached with a log.
- Take the shared lock with `flock -o` so child processes do not inherit it. Stop your own processes by PID, never `pkill -f`. Fault injection stays inside Sentinel's processes, network namespaces and loop devices.
- Align toolchains with `bench/hosts/align-toolchain.sh` and `bench/hosts/build-podman.sh`; never install a package that conflicts with Docker CE.
- Verify a change with the test binaries that cover it plus `cargo lint-linux`. Full suites run once per wave gate, not per change.

## Commands

Aliases live in `.cargo/config.toml`, all `--locked` (a dependency change commits `Cargo.lock`). Tests use cargo-nextest.

| Purpose | Command |
|---|---|
| Portable checks | `cargo fmt-check`, `cargo lint`, `cargo test-cli`, `cargo release-cli`, `cargo licenses` (cargo-deny) |
| Linux roles | `cargo lint-linux`, `cargo test-server`, `cargo test-worker`, `cargo test-linux`, `cargo release-linux` |
| Benchmarks | `cargo bench-noop --runtime direct --warm-state warm`; `sentinel-bench --contract <file> --lane <id> --condition <c>` |
| Web | `pnpm -C web install`, `typecheck`, `build`, `test:unit`; browser test `cargo test -p sentinel-api --test web_browser -- --ignored` |

Podman suites need `SENTINEL_PODMAN_TESTS=1` as the rootless account; microVM suites need `SENTINEL_MICROVM_TESTS=1` on `kvm-host`.

## Layout

| Path | Contents |
|---|---|
| `crates/sentinel-core` | IDs, state machine, failure classes |
| `crates/sentinel-protocol` | errors, idempotency, cursors, limits, negotiation, guest-agent framing |
| `crates/sentinel-pipeline` | `.sentinel.yml` loader, schema, compiler |
| `crates/sentinel-store` | SQLite metadata store (single durable writer), dispatch, logs, objects, retention, backup |
| `crates/sentinel-auth` | passwords, opaque secrets, cookies/CSRF, TOTP, sealed storage |
| `crates/sentinel-api` | the controller's HTTP API |
| `crates/sentinel-link` | worker link (mutual TLS, framing, controller dispatch loop, worker reconnect, Tailcat) |
| `crates/sentinel-worker` | Linux executor: workspaces, checkout, rootless Podman, Firecracker microVMs, log spool |
| `crates/sentinel-agent` | static guest agent for microVMs |
| `crates/sentinel-git`, `-intake`, `-github`, `-checks`, `-mail`, `-s3`, `-cache` | Git, run intake, GitHub sign-in, Checks outbox, email, S3, worker cache |
| `crates/sentinel` | CLI, host-local `admin`, Linux `server`/`worker` roles |
| `crates/sentinel-bench`, `-probes` | benchmark runner and B11 harness, feasibility probes |
| `web/` | `sentinel-web` (TanStack Start, React, Tailwind v4, pnpm), its own Node process |
| `bench/` | benchmark records, frozen contracts, harnesses, host setup |
| `examples/` | sanitized configs, deployment examples, pilot pipelines |

## Conventions

- Rust 1.97, edition 2024, `unsafe_op_in_unsafe_fn = deny`; every `unsafe` block has a `// SAFETY:` comment.
- Durations are monotonic nanoseconds; wall-clock time is provenance only. Unmeasured fields are absent, never zero.
- Diagnostics never echo configuration or payloads that may hold credentials.
- Tests cover behavior and failure paths, not the implementation's shape.
- Sandboxes follow the host: rootless Podman without KVM, Firecracker for Linux guests on KVM hosts. No QEMU. Jobs have no network unless the worker sets `job_network = "egress"`.
- One GitHub App; features needing more permissions ask for them only when a tenant enables them.
