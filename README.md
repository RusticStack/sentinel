# Sentinel

A purpose-built, fully open-source, self-hosted CI engine designed from scratch for maximum performance: fast PR feedback, local-first caching, efficient multi-machine scheduling, and readable diagnostics for humans and coding agents.

**Status: planning; the new CI engine is not implemented yet.** See [plan.md](plan.md) for architecture, milestones, performance targets, and release criteria.

The new implementation will use a Rust core and its own pipeline format. GitHub will remain the forge, with results published through Checks. The default deployment will use embedded SQLite and Sentinel-owned local storage, with optional external S3 and Tailcat-connected workers.

One deployment will support multiple organizations and personal namespaces, super-admin registration controls, OAuth-authenticated CLI/MCP, CLI-managed secrets, and tenant-scoped workers/data. [Lockwell](docs/lockwell-migration.md) is a representative workload whose CI adapts to Sentinel; it does not dictate the engine's architecture.

The performance ambition is **sub-minute warm PR checks on the same hardware that previously took five minutes or more**. See [performance research](docs/performance-research.md) for Blacksmith/Depot mechanisms, actual Lockwell timings, caching design, and the measurement plan. See [OAuth and secrets](docs/auth-and-secrets.md) for human/agent access. Targets are not yet measured Sentinel results.

## Legacy dashboard

The original Deno/Fresh GitHub Actions runner dashboard and its full history are preserved on [`legacy`](https://github.com/RusticStack/sentinel/tree/legacy). This `main` branch begins the from-scratch replacement.

## License

[MIT](LICENSE).
