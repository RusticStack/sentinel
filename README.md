# Sentinel

A purpose-built, fully open-source, self-hosted CI engine designed from scratch for maximum performance: fast PR feedback, local-first caching, efficient multi-machine scheduling, and readable diagnostics for humans and coding agents.

**Status: early development; runtime/measurement foundations, core/store/protocol contracts, the pipeline compiler, durable authorization, local login/sessions, scoped API credentials, GitHub sign-in, admission policy, second-factor step-up and tenant suspension/pool grants are implemented. The authenticated API surface and job execution are next.** See [plan.md](plan.md) for architecture, milestones, performance targets, and release criteria. The [Parts 01–02 audit](docs/parts-01-02-audit.md) records open execution-integration gates.

Start development from [TODO.md](TODO.md): ordered work packages, stable task IDs, dependencies, the first runnable server/worker slice, and verification gates.

See [Rust foundation](docs/rust-foundation.md) for the pinned toolchain, build commands, platform/feature matrix, and dependency boundaries.

See [CLI and configuration](docs/configuration.md) to validate configuration, start the separate Linux processes, and shut them down.

For contributor prerequisites, daily check/build commands, and a local two-process setup, see [Development](docs/development.md).

See [Core contracts](docs/core-contracts.md) for typed identifiers, the fenced job/run state machine, failure classes and cancellation.

See [Storage](docs/storage.md) for the SQLite metadata store, the engine decision, and the durable single-writer acknowledgement policy.

See [Authorization](docs/authorization.md) for namespaces, human/service identities, memberships, explicit repo grants and live scoped queries.

See [Local authentication](docs/local-authentication.md) for host-local first-admin bootstrap, Argon2id passwords, opaque sessions, cookie/CSRF policy and audited recovery.

See [API credentials](docs/api-credentials.md) for the scoped, expiring bearer credentials that authenticate the CLI and API before OAuth.

See [GitHub sign-in](docs/github-sign-in.md) for the authorization-code flow, verified identity linking and what separates proof from admission.

See [Admission](docs/admission.md) for registration policy, invitations, pending accounts, and the separate decisions of creating a tenant and binding a forge installation.

See the [Part 03 audit](docs/part-03-audit.md) for what was re-read, what was found and fixed, and what is deliberately left as is.

See [Tenancy](docs/tenancy.md) for tenant suspension, what it revokes and cancels, the authorization epoch that long-lived streams re-check, and pool grants.

See [Step-up](docs/step-up.md) for second factors, sealed TOTP seeds, recovery codes, and the step-up that gates changes to who can authenticate.

See [Protocol contracts](docs/protocol.md) for structured errors, idempotency, event cursors, size limits and worker capability negotiation.

See [Pipeline schema](docs/pipeline-schema.md) for the strict, bounded `.sentinel.yml` format and its deterministic compiler.

See [Compatibility](docs/compatibility.md) for how each schema, blob format, database migration and protocol version may change.

See [Runtime foundations](docs/runtime-foundation.md) for structured diagnostics, correlation IDs, monotonic phase timing, and bounded I/O/CPU execution lanes.

See [Benchmarking](docs/benchmarking.md) for the machine-readable benchmark runner and the no-op rootless-runtime baseline, [CI baseline](docs/ci-baseline.md) for the measured Lockwell CI topology and timings Sentinel must beat, and [feasibility probes](docs/feasibility-probes.md) for the SQLite, Podman, reflink and Tailcat decisions.

The new implementation will use a Rust core and its own pipeline format. GitHub will remain the forge, with results published through Checks. The default deployment will use embedded SQLite and Sentinel-owned local storage, with optional external S3 and Tailcat-connected workers.

One deployment will support multiple organizations and personal namespaces, super-admin registration controls, OAuth-authenticated CLI/MCP, CLI-managed secrets, and tenant-scoped workers/data. [Lockwell](docs/lockwell-migration.md) is a representative workload whose CI adapts to Sentinel; it does not dictate the engine's architecture.

The performance ambition is **sub-minute warm PR checks on the same hardware that previously took five minutes or more**. See [performance research](docs/performance-research.md) for Blacksmith/Depot mechanisms, actual Lockwell timings, caching design, and the measurement plan. See [OAuth and secrets](docs/auth-and-secrets.md) for human/agent access. Targets are not yet measured Sentinel results.

## Legacy dashboard

The original Deno/Fresh GitHub Actions runner dashboard and its full history are preserved on [`legacy`](https://github.com/RusticStack/sentinel/tree/legacy). This `main` branch begins the from-scratch replacement.

## License

[MIT](LICENSE).
