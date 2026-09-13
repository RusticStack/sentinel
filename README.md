# Sentinel

A purpose-built, fully open-source, self-hosted CI engine designed from scratch for maximum performance: fast PR feedback, local-first caching, efficient multi-machine scheduling, and readable diagnostics for humans and coding agents.

**Status: early development; CLI configuration and Linux server/worker process lifecycles are implemented, but the CI engine is not implemented yet.** See [plan.md](plan.md) for architecture, milestones, performance targets, and release criteria.

Start development from [TODO.md](TODO.md): ordered work packages, stable task IDs, dependencies, the first runnable server/worker slice, and verification gates.

See [Rust foundation](docs/rust-foundation.md) for the pinned toolchain, build commands, platform/feature matrix, and dependency boundaries.

See [CLI and configuration](docs/configuration.md) to validate configuration, start the separate Linux processes, and shut them down.

For contributor prerequisites, daily check/build commands, and a local two-process setup, see [Development](docs/development.md).

See [Core contracts](docs/core-contracts.md) for typed identifiers, the fenced job/run state machine, failure classes and cancellation.

See [Storage](docs/storage.md) for the SQLite metadata store, the engine decision, and the durable single-writer acknowledgement policy.

See [Protocol contracts](docs/protocol.md) for structured errors, idempotency, event cursors, size limits and worker capability negotiation.

See [Runtime foundations](docs/runtime-foundation.md) for structured diagnostics, correlation IDs, monotonic phase timing, and bounded I/O/CPU execution lanes.

See [Benchmarking](docs/benchmarking.md) for the machine-readable benchmark runner and the no-op rootless-runtime baseline, [CI baseline](docs/ci-baseline.md) for the measured Lockwell CI topology and timings Sentinel must beat, and [feasibility probes](docs/feasibility-probes.md) for the SQLite, Podman, reflink and Tailcat decisions.

The new implementation will use a Rust core and its own pipeline format. GitHub will remain the forge, with results published through Checks. The default deployment will use embedded SQLite and Sentinel-owned local storage, with optional external S3 and Tailcat-connected workers.

One deployment will support multiple organizations and personal namespaces, super-admin registration controls, OAuth-authenticated CLI/MCP, CLI-managed secrets, and tenant-scoped workers/data. [Lockwell](docs/lockwell-migration.md) is a representative workload whose CI adapts to Sentinel; it does not dictate the engine's architecture.

The performance ambition is **sub-minute warm PR checks on the same hardware that previously took five minutes or more**. See [performance research](docs/performance-research.md) for Blacksmith/Depot mechanisms, actual Lockwell timings, caching design, and the measurement plan. See [OAuth and secrets](docs/auth-and-secrets.md) for human/agent access. Targets are not yet measured Sentinel results.

## Legacy dashboard

The original Deno/Fresh GitHub Actions runner dashboard and its full history are preserved on [`legacy`](https://github.com/RusticStack/sentinel/tree/legacy). This `main` branch begins the from-scratch replacement.

## License

[MIT](LICENSE).
