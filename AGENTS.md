# Working on Sentinel

**Rule one: write the most optimized code possible, every time.** Sentinel exists to beat other CI engines on the same hardware, so every change is judged on its cost: no allocation, copy, syscall, lock, or database round trip that the work does not require; hot paths are branch-light and cache-friendly; data structures are chosen for the access pattern; measurements, not guesses, justify anything slower than the obvious fast path. Correctness and bounded resource usage are not traded away for speed, but slow-and-simple is not an acceptable default.

Sentinel is a performance-first, self-hosted Rust CI engine. Read [README.md](README.md), then use [TODO.md](TODO.md) as the execution tracker and [plan.md](plan.md) as the design reference.

## Workflow

- Pick the task named under **Next task** in `TODO.md` unless told otherwise. Keep task IDs stable.
- Mark a task `[x]` only when code, docs and verification exist. Add a completion-log row with the commit title, linked docs and the actual test/benchmark evidence, then update **Next task**.
- Do not invent measurements. Record unavailable hardware or blocked prerequisites as `Blocked by: ...`.
- Preserve the boundaries in the backlog: separate server/worker processes, tenant ownership, durable transitions, bounded resource usage. Add crates only when useful.
- Commit with a conventional prefix (`feat:`, `build:`, `docs:`) and a message that describes behavior, not files.
- **Tests run only on the verification VPS**, never on a workstation or in WSL: every test of any size — a single test binary, the full suites, the web browser test, benchmarks. Local work stops at formatting, `cargo check`/lint and `pnpm -C web typecheck`. The VPS is named in the git-ignored `.env` ([`.env.example`](.env.example)); see [development](docs/development.md#where-tests-run). It is shared with production services: run under `nice`/`ionice` with limited jobs, and when it is heavily loaded skip the run and record the verification as pending — never invent results.
- Verify a change with the tests that cover it (the affected test binaries, plus `cargo lint`/`cargo lint-linux`). Run the full suites once per Part of `TODO.md`, when its last task is done — not after every task or change — and keep stress runs short. The test aliases run through [cargo-nextest](https://nexte.st), every test of every binary in parallel: a full `test-cli` plus `test-linux` takes about 4 minutes on the VPS, against about 25 with plain `cargo test`.

## Commands

Run from the repository root; aliases live in `.cargo/config.toml`.

| Purpose | Command |
|---|---|
| Portable checks (all OSes) | `cargo fmt-check`, `cargo lint`, `cargo test-cli`, `cargo release-cli` |
| Linux role checks | `cargo lint-linux`, `cargo test-server`, `cargo test-worker`, `cargo test-linux`, `cargo release-linux` |
| Benchmark runner | `cargo bench-noop --runtime direct --warm-state warm` |
| Feasibility probes | `cargo probe sqlite --path /tmp/d.sqlite` |
| Web interface | `pnpm -C web install`, `pnpm -C web typecheck`, `pnpm -C web build`; browser test `cargo test -p sentinel-api --test web_browser -- --ignored` (Node, Edge/Chrome/Chromium) |

All aliases pass `--locked`; a dependency change must update and commit `Cargo.lock` (use `cargo update --workspace --offline` for new members). Apply formatting with `cargo fmt --all`.

Test commands in this table run on the verification VPS, not locally ([development](docs/development.md#where-tests-run)).

## Layout

| Path | Purpose |
|---|---|
| `crates/sentinel-core` | Pure contracts: IDs, state machine, failure classes; see [docs/core-contracts.md](docs/core-contracts.md) |
| `crates/sentinel-auth` | Password hashing, opaque secrets, cookie/CSRF policy, TOTP/recovery codes, sealed storage; see [local authentication](docs/local-authentication.md), [API credentials](docs/api-credentials.md), [step-up](docs/step-up.md) |
| `crates/sentinel-link` | Worker link: generated TLS identity, pinned mutual TLS, full-duplex framing, hello/heartbeat, the controller's dispatch loop (`controller` feature) and the worker's reconnect loop; see [worker link](docs/worker-link.md) |
| `crates/sentinel-github` | GitHub sign-in: bounded HTTPS client, code exchange, verified identity; see [GitHub sign-in](docs/github-sign-in.md) |
| `crates/sentinel-git` | Bounded Git: exact-revision checkout, file-at-revision reads, one credential and process-group discipline; shared by the worker and the controller's source resolution |
| `crates/sentinel-store` | SQLite metadata store, single durable writer; see [docs/storage.md](docs/storage.md), [retention](docs/retention.md) |
| `crates/sentinel-s3` | Optional external S3 client: Signature V4, multipart with resume, range reads, abort cleanup, the endpoint compatibility matrix; see [docs/s3.md](docs/s3.md) |
| `crates/sentinel-checks` | Durable check delivery: the outbox lane and the GitHub Checks publisher; see [checks](docs/checks.md) |
| `crates/sentinel-api` | The controller's HTTP API; see [API](docs/api.md) |
| `crates/sentinel-worker` | Linux executor: fresh workspaces, exact-revision checkout, rootless Podman containers, attempt lifecycle, log redaction and spool; see [executor](docs/executor.md), [logs](docs/logs.md) |
| `crates/sentinel-protocol` | Errors, idempotency, cursors, limits, negotiation; see [docs/protocol.md](docs/protocol.md) |
| `crates/sentinel-pipeline` | `.sentinel.yml` loader, schema and compiler; see [docs/pipeline-schema.md](docs/pipeline-schema.md) |
| `crates/sentinel-cache` | Worker-local cache metadata: scope paths, sealed-generation manifests, explainable hit/miss reasons; see [docs/cache.md](docs/cache.md) |
| `crates/sentinel` | CLI (`pipeline`, `api` client, host-local `admin`) plus Linux `server`/`worker` roles behind features |
| `crates/sentinel-bench` | Benchmark runner; see [docs/benchmarking.md](docs/benchmarking.md) |
| `crates/sentinel-probes` | SQLite/clone probes; see [docs/feasibility-probes.md](docs/feasibility-probes.md) |
| `web/` | The web interface, `sentinel-web` (Nuxt 4, Vue, TypeScript, Nuxt UI; pnpm): pages, live event streams, the proxy to the API, its browser test and U01 benchmark; see [web interface](docs/web-ui.md) |
| `bench/` | Committed machine-readable benchmark records |
| `fixtures/` | Valid and invalid pipeline fixtures exercised by tests |
| `docs/` | Contracts and guides: [development](docs/development.md), [configuration](docs/configuration.md), [runtime foundations](docs/runtime-foundation.md) |
| `examples/` | Sanitized configuration files |
| `.local/`, `data/`, `target/` | Ignored local state; never commit credentials or generated data |

## Conventions

- Rust 1.97, edition 2024, `unsafe_op_in_unsafe_fn = deny`; every `unsafe` block carries a `// SAFETY:` comment.
- Durations are monotonic `Instant` measurements in nanoseconds; wall-clock timestamps are provenance only. Unmeasured fields are absent, never zero.
- Diagnostics must not echo configuration or parser payloads that could contain credentials.
- Tests cover behavior and failure paths; do not add tests that merely mirror the implementation.
- Versioned contracts (pipeline schema, run spec format, migrations, error/explain schemas, cursors, worker protocol) change only under [docs/compatibility.md](docs/compatibility.md).
