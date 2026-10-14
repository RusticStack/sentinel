# Sentinel

A purpose-built, fully open-source, self-hosted CI engine designed from scratch for maximum performance: fast PR feedback, local-first caching, efficient multi-machine scheduling, and readable diagnostics for humans and coding agents.

**Status: early development.** Parts 00–13 of [TODO.md](TODO.md) are implemented; Part 14 (same-hardware optimization and pilots) is in progress and Part 15 (release) has not started. [TODO.md](TODO.md) is the execution tracker with per-task evidence and open work; [plan.md](plan.md) is the design reference (architecture, milestones, performance targets, release criteria). The performance targets are not measured Sentinel results.

The ambition is **sub-minute warm PR checks on hardware that previously took five minutes or more**; see [performance research](docs/performance-research.md).

## What it is

- A Rust core with its own pipeline format ([`.sentinel.yml`](docs/pipeline-schema.md)), one `sentinel` binary with a CLI, a controller (`server`) and a Linux executor (`worker`), and an optional Node web interface ([web interface](docs/web-ui.md)).
- Embedded SQLite metadata and Sentinel-owned local storage, with optional external S3 and Tailcat-connected workers.
- One deployment hosts several organizations and personal namespaces, with super-admin registration controls, OAuth-authenticated CLI and MCP, CLI-managed secrets, and tenant-scoped workers and data.
- Provider-independent Git repositories (manual, generic hook and opt-in polling intake) work with Gitea, Forgejo, GitLab and bare repositories. GitHub is the one native forge integration (GitHub App, native PR Checks); other forge-native PR/MR integrations are deferred ([plan](plan.md#git-sources-and-forge-boundaries)).
- [Lockwell](docs/lockwell-migration.md) is a representative workload whose CI adapts to Sentinel; it does not dictate the architecture.

**Platforms:** Linux runs everything (server, worker, CLI); Windows runs the CLI; macOS is not supported ([platform matrix](docs/rust-foundation.md#platform-and-feature-matrix)).

## Quick start

Needs the pinned Rust toolchain (`rust-toolchain.toml`). Full prerequisites are in [Development](docs/development.md).

```sh
cargo run -p sentinel -- pipeline validate <file>   # offline check of a .sentinel.yml, any platform
cargo dev-server --data-dir "$PWD/data/controller"         # Linux terminal one
cargo dev-worker --data-dir "$PWD/data/worker"             # Linux terminal two
```

Aliases live in `.cargo/config.toml`; the command table is in [AGENTS.md](AGENTS.md). First administrator setup is described under [operator first run](docs/development.md#operator-first-run).

## Documentation

Contributors start with [AGENTS.md](AGENTS.md) and [Development](docs/development.md). Each contract lives in one topical document under [`docs/`](docs/):

- Foundations: [Rust foundation](docs/rust-foundation.md), [configuration and CLI](docs/configuration.md), [runtime foundations](docs/runtime-foundation.md), [core contracts](docs/core-contracts.md), [protocol](docs/protocol.md), [compatibility](docs/compatibility.md), [storage](docs/storage.md), [backup](docs/backup.md), [retention](docs/retention.md), [upgrades](docs/upgrades.md), [resilience](docs/resilience.md).
- Identity: [authorization](docs/authorization.md), [local authentication](docs/local-authentication.md), [API credentials](docs/api-credentials.md), [GitHub sign-in](docs/github-sign-in.md), [admission](docs/admission.md), [tenancy](docs/tenancy.md), [step-up](docs/step-up.md), [sealed storage](docs/sealed-storage.md), [scoped secrets](docs/secrets.md), [OAuth and secrets](docs/auth-and-secrets.md), [OAuth](docs/oauth.md).
- Sources and feedback: [sources](docs/sources.md), [intake](docs/intake.md), [checks](docs/checks.md), [pipeline schema](docs/pipeline-schema.md), [recipes](docs/recipes.md), [hash_files](docs/hash-files.md).
- Execution: [executor](docs/executor.md), [worker link](docs/worker-link.md), [logs](docs/logs.md), [cancellation](docs/cancellation.md), [reconciliation](docs/reconciliation.md), [vertical slice](docs/vertical-slice.md).
- Interfaces: [API](docs/api.md), [CLI](docs/cli.md), [MCP](docs/mcp.md), [monitoring](docs/monitoring.md), [diagnostics](docs/diagnostics.md), [web interface](docs/web-ui.md).
- Performance: [benchmarking](docs/benchmarking.md), [CI baseline](docs/ci-baseline.md), [benchmark contracts](docs/benchmark-contracts.md), [latency budgets](docs/latency-budgets.md), [feasibility probes](docs/feasibility-probes.md), [performance research](docs/performance-research.md).

## Legacy dashboard

The original Deno/Fresh GitHub Actions runner dashboard and its history are preserved on [`legacy`](https://github.com/RusticStack/sentinel/tree/legacy). This `main` branch is the from-scratch replacement.

## License

[MIT](LICENSE).
