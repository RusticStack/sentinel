# Sentinel

A purpose-built, fully open-source, self-hosted CI engine designed from scratch for maximum performance: fast PR feedback, local-first caching, efficient multi-machine scheduling, and readable diagnostics for humans and coding agents.

**Status: early development; Parts 00–11 are implemented.** Part 11 adds versioned, bounded diagnostics and MCP over stdio and OAuth-protected Streamable HTTP, including supported client registration and metadata discovery. Part 10 adds sealed tenant/repository secret versions, delegated CLI management and atomic env-file import, explicit job/step bindings, protocol-10 fenced delivery, environment and file injection, redaction, cleanup/recovery, and per-tenant private-registry authorization. See [Diagnostics](docs/diagnostics.md), [MCP](docs/mcp.md), [Secrets](docs/secrets.md), and [TODO.md](TODO.md) for contracts and verification evidence. **See [plan.md](plan.md)** for architecture, milestones, performance targets, and release criteria. The [Parts 01–02 audit](docs/parts-01-02-audit.md) records the execution-integration gates it found and how each was closed.

Start development from [TODO.md](TODO.md): ordered work packages, stable task IDs, dependencies, the first runnable server/worker slice, and verification gates.

**Supported platforms:** Linux runs everything (the server, the worker and the CLI); Windows runs the CLI. macOS is not supported. The [platform matrix](docs/rust-foundation.md#platform-and-feature-matrix) lists the target triples.

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

See the [Parts 00–09 audit](docs/parts-00-09-audit.md) for the full re-audit of every task through Part 09: each finding with its fix, commit and regression test, what was kept by design, what moved to a later task, and the verification evidence.

See the [Parts 09–11 audit](docs/parts-09-11-audit.md) for the second re-audit of the OAuth server and CLI, secret management and delivery, and diagnostics and MCP: every finding with its outcome, commit and test, how the five fix branches were merged, the leftovers and flaky tests closed afterwards, and the final verification. X07 (real MCP clients) remains open.

See [Vertical slice](docs/vertical-slice.md) for what Part 04 was exercised against and what held.

See [API](docs/api.md) for the one authenticated surface the CLI, the page and later agents share.

See [Sources](docs/sources.md) for tenant-owned repository bindings, sealed HTTPS/SSH deploy credentials delivered per acknowledged attempt, checkout trust, and GitHub App associations with scoped short-lived tokens.

See [Intake](docs/intake.md) for the durable event path: repository hook secrets, raw-body GitHub webhook signatures, deduplicated deliveries acknowledged after commit, the bounded resolution lane, and the spooling `post-receive` relay.

See [Checks](docs/checks.md) for durable GitHub aggregate and per-job feedback, retry and rate-limit handling, publication identity, and run links.

See [Reconciliation](docs/reconciliation.md) for what a controller or worker restart settles, and how nothing that may have run is replayed.

See [Cancellation](docs/cancellation.md) for cancel as desired state, graceful then forced termination, timeouts, and lease expiry.

See [Logs](docs/logs.md) for how step output reaches the controller: redacted, spooled, windowed, acknowledged after fsync, never lost in silence.

See [Executor](docs/executor.md) for what a job runs in: a fresh workspace, the pinned commit, a rootless container with the job's limits and every capability dropped, and the attempt lifecycle reported under its fence.

See [Worker link](docs/worker-link.md) for one-time worker enrollment, worker-generated TLS identities pinned in both directions, heartbeat sessions that renew leases, and the wake-driven dispatch loop: the ready queue is the database, a reservation is an attempt, offers are fenced and acknowledged or lapse back to the queue.

See [Tenancy](docs/tenancy.md) for tenant suspension, what it revokes and cancels, the authorization epoch that long-lived streams re-check, and pool grants.

See [Step-up](docs/step-up.md) for second factors, sealed TOTP seeds, recovery codes, and the step-up that gates changes to who can authenticate.

See [Sealed storage](docs/sealed-storage.md) for the versioned encryption format, ownership binding, and offline master-key rotation and restore.

See [Scoped secrets](docs/secrets.md) for tenant and repository secret records, explicit job and step bindings, allowlists, precedence, and audit metadata.

See [Protocol contracts](docs/protocol.md) for structured errors, idempotency, event cursors, size limits and worker capability negotiation.

See [Pipeline schema](docs/pipeline-schema.md) for the strict, bounded `.sentinel.yml` format and its deterministic compiler.

See [Compatibility](docs/compatibility.md) for how each schema, blob format, database migration and protocol version may change.

See [Runtime foundations](docs/runtime-foundation.md) for structured diagnostics, correlation IDs, monotonic phase timing, and bounded I/O/CPU execution lanes.

See [Benchmarking](docs/benchmarking.md) for the machine-readable benchmark runner and the no-op rootless-runtime baseline, [CI baseline](docs/ci-baseline.md) for the measured Lockwell CI topology and timings Sentinel must beat, [benchmark contracts](docs/benchmark-contracts.md) for the frozen checks and conditions Part 14 is measured under, and [feasibility probes](docs/feasibility-probes.md) for the SQLite, Podman, reflink and Tailcat decisions.

The new implementation will use a Rust core and its own pipeline format. Part 05 will add provider-independent Git repository connections and manual, generic hook and opt-in polling intake for Gitea, Forgejo, GitLab and bare repositories, with results in Sentinel's UI/API. GitHub is the first native forge integration: GitHub App access and native PR Checks are required in Part 05; other forge-native PR/MR integrations are deferred. See [Git sources and forge boundaries](plan.md#git-sources-and-forge-boundaries). The default deployment will use embedded SQLite and Sentinel-owned local storage, with optional external S3 and Tailcat-connected workers.

One deployment will support multiple organizations and personal namespaces, super-admin registration controls, OAuth-authenticated CLI/MCP, CLI-managed secrets, and tenant-scoped workers/data. [Lockwell](docs/lockwell-migration.md) is a representative workload whose CI adapts to Sentinel; it does not dictate the engine's architecture.

The performance ambition is **sub-minute warm PR checks on the same hardware that previously took five minutes or more**. See [performance research](docs/performance-research.md) for Blacksmith/Depot mechanisms, actual Lockwell timings, caching design, and the measurement plan. See [OAuth and secrets](docs/auth-and-secrets.md) for human/agent access. Targets are not yet measured Sentinel results.

## Legacy dashboard

The original Deno/Fresh GitHub Actions runner dashboard and its full history are preserved on [`legacy`](https://github.com/RusticStack/sentinel/tree/legacy). This `main` branch begins the from-scratch replacement.

## License

[MIT](LICENSE).
