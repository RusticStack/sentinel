# Working on Sentinel

Sentinel is a performance-first, self-hosted Rust CI engine. Read [README.md](README.md), then use [TODO.md](TODO.md) as the execution tracker and [plan.md](plan.md) as the design reference.

## Workflow

- Pick the task named under **Next task** in `TODO.md` unless told otherwise. Keep task IDs stable.
- Mark a task `[x]` only when code, docs and verification exist. Add a completion-log row with the commit title, linked docs and the actual test/benchmark evidence, then update **Next task**.
- Do not invent measurements. Record unavailable hardware or blocked prerequisites as `Blocked by: ...`.
- Preserve the boundaries in the backlog: separate server/worker processes, tenant ownership, durable transitions, bounded resource usage. Add crates only when useful.
- Commit with a conventional prefix (`feat:`, `build:`, `docs:`) and a message that describes behavior, not files.

## Commands

Run from the repository root; aliases live in `.cargo/config.toml`.

| Purpose | Command |
|---|---|
| Portable checks (all OSes) | `cargo fmt-check`, `cargo lint`, `cargo test-cli`, `cargo release-cli` |
| Linux role checks | `cargo lint-linux`, `cargo test-server`, `cargo test-worker`, `cargo test-linux`, `cargo release-linux` |
| Benchmark runner | `cargo bench-noop --runtime direct --warm-state warm` |

All aliases pass `--locked`; a dependency change must update and commit `Cargo.lock` (use `cargo update --workspace --offline` for new members). Apply formatting with `cargo fmt --all`.

On Windows, run the Linux checks inside WSL2 with `export CARGO_TARGET_DIR=target/wsl`. WSL2 verifies process/signal behavior; it is not a production benchmark host.

## Layout

| Path | Purpose |
|---|---|
| `crates/sentinel` | CLI plus Linux `server`/`worker` roles behind features |
| `crates/sentinel-bench` | Benchmark runner; see [docs/benchmarking.md](docs/benchmarking.md) |
| `bench/` | Committed machine-readable benchmark records |
| `docs/` | Contracts and guides: [development](docs/development.md), [configuration](docs/configuration.md), [runtime foundations](docs/runtime-foundation.md) |
| `examples/` | Sanitized configuration files |
| `.local/`, `data/`, `target/` | Ignored local state; never commit credentials or generated data |

## Conventions

- Rust 1.97, edition 2024, `unsafe_op_in_unsafe_fn = deny`; every `unsafe` block carries a `// SAFETY:` comment.
- Durations are monotonic `Instant` measurements in nanoseconds; wall-clock timestamps are provenance only. Unmeasured fields are absent, never zero.
- Diagnostics must not echo configuration or parser payloads that could contain credentials.
- Tests cover behavior and failure paths; do not add tests that merely mirror the implementation.
