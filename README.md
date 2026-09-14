# Sentinel

A purpose-built, fully open-source, self-hosted CI engine designed from scratch for maximum performance: fast PR feedback, local-first caching, efficient multi-machine scheduling, and readable diagnostics for humans and coding agents.

**Status: early development; runtime/measurement foundations, core/store/protocol contracts, the pipeline compiler, durable authorization, local login/sessions, scoped API credentials, GitHub sign-in, admission policy, second-factor step-up and tenant suspension/pool grants, worker enrollment/sessions, the durable dispatch loop and the first executor (fresh workspaces, exact-revision checkout, rootless Podman containers with enforced limits and no privileges, phase reports over the link) and W04's step semantics (`sh -e`/Bash, environment precedence, bounded timeouts, worker-phase `if` conditions, exit/signal/OOM/timeout/runtime taxonomy, per-phase timings stored with the attempt) and W05's log pipeline (redacted before leaving the worker, spooled to disk, sent within a bounded window, acknowledged only once synced on the controller, complete with declared gaps) and W06's cancellation (durable desired state, TERM-then-KILL of the container's process group, queue and execution timeouts, lease expiry that never replays uncertain work) and W07's restart reconciliation (the controller settles expired leases, unanswered offers and orphaned attempts from the rows before admitting anyone; the worker reaps its containers and workspaces, delivers leftover spools and abandons the attempts under their fences) and W08's authenticated API (dispatch, status, cancel, rerun, log tail/follow, worker status), `sentinel api` CLI and first page are implemented, and W09's vertical-slice exercise closes Part 04: success, failure, duplicate offers, lost acknowledgements, cancels during preparation and run, worker and controller restarts, stale leases and network loss, with no duplicate execution and nothing orphaned. G01's tenant-owned source bindings are implemented: approved clone URLs/refs/pipeline paths, sealed HTTPS and SSH deploy credentials delivered only to an acknowledged attempt under protocol 2, recipient-side CA/known-hosts trust, and optional GitHub App associations minting short-lived repository-scoped `contents: read` tokens. G02 adds the shared durable intake path: per-repository hook secrets and App-webhook signature verification over raw bodies, deduplicated tenant-owned deliveries acknowledged only after commit, a bounded resolution lane that validates the source before G03 compiles it, and a spooling `post-receive` relay example. GitHub Checks follow.** See [plan.md](plan.md) for architecture, milestones, performance targets, and release criteria. The [Parts 01–02 audit](docs/parts-01-02-audit.md) records open execution-integration gates.

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

See [Vertical slice](docs/vertical-slice.md) for what Part 04 was exercised against and what held.

See [API](docs/api.md) for the one authenticated surface the CLI, the page and later agents share.

See [Sources](docs/sources.md) for tenant-owned repository bindings, sealed HTTPS/SSH deploy credentials delivered per acknowledged attempt, checkout trust, and GitHub App associations with scoped short-lived tokens.

See [Intake](docs/intake.md) for the durable event path: repository hook secrets, raw-body GitHub webhook signatures, deduplicated deliveries acknowledged after commit, the bounded resolution lane, and the spooling `post-receive` relay.

See [Reconciliation](docs/reconciliation.md) for what a controller or worker restart settles, and how nothing that may have run is replayed.

See [Cancellation](docs/cancellation.md) for cancel as desired state, graceful then forced termination, timeouts, and lease expiry.

See [Logs](docs/logs.md) for how step output reaches the controller: redacted, spooled, windowed, acknowledged after fsync, never lost in silence.

See [Executor](docs/executor.md) for what a job runs in: a fresh workspace, the pinned commit, a rootless container with the job's limits and every capability dropped, and the attempt lifecycle reported under its fence.

See [Worker link](docs/worker-link.md) for one-time worker enrollment, worker-generated TLS identities pinned in both directions, heartbeat sessions that renew leases, and the wake-driven dispatch loop: the ready queue is the database, a reservation is an attempt, offers are fenced and acknowledged or lapse back to the queue.

See [Tenancy](docs/tenancy.md) for tenant suspension, what it revokes and cancels, the authorization epoch that long-lived streams re-check, and pool grants.

See [Step-up](docs/step-up.md) for second factors, sealed TOTP seeds, recovery codes, and the step-up that gates changes to who can authenticate.

See [Protocol contracts](docs/protocol.md) for structured errors, idempotency, event cursors, size limits and worker capability negotiation.

See [Pipeline schema](docs/pipeline-schema.md) for the strict, bounded `.sentinel.yml` format and its deterministic compiler.

See [Compatibility](docs/compatibility.md) for how each schema, blob format, database migration and protocol version may change.

See [Runtime foundations](docs/runtime-foundation.md) for structured diagnostics, correlation IDs, monotonic phase timing, and bounded I/O/CPU execution lanes.

See [Benchmarking](docs/benchmarking.md) for the machine-readable benchmark runner and the no-op rootless-runtime baseline, [CI baseline](docs/ci-baseline.md) for the measured Lockwell CI topology and timings Sentinel must beat, and [feasibility probes](docs/feasibility-probes.md) for the SQLite, Podman, reflink and Tailcat decisions.

The new implementation will use a Rust core and its own pipeline format. Part 05 will add provider-independent Git repository connections and manual, generic hook and opt-in polling intake for Gitea, Forgejo, GitLab and bare repositories, with results in Sentinel's UI/API. GitHub is the first native forge integration: GitHub App access and native PR Checks are required in Part 05; other forge-native PR/MR integrations are deferred. See [Git sources and forge boundaries](plan.md#git-sources-and-forge-boundaries). The default deployment will use embedded SQLite and Sentinel-owned local storage, with optional external S3 and Tailcat-connected workers.

One deployment will support multiple organizations and personal namespaces, super-admin registration controls, OAuth-authenticated CLI/MCP, CLI-managed secrets, and tenant-scoped workers/data. [Lockwell](docs/lockwell-migration.md) is a representative workload whose CI adapts to Sentinel; it does not dictate the engine's architecture.

The performance ambition is **sub-minute warm PR checks on the same hardware that previously took five minutes or more**. See [performance research](docs/performance-research.md) for Blacksmith/Depot mechanisms, actual Lockwell timings, caching design, and the measurement plan. See [OAuth and secrets](docs/auth-and-secrets.md) for human/agent access. Targets are not yet measured Sentinel results.

## Legacy dashboard

The original Deno/Fresh GitHub Actions runner dashboard and its full history are preserved on [`legacy`](https://github.com/RusticStack/sentinel/tree/legacy). This `main` branch begins the from-scratch replacement.

## License

[MIT](LICENSE).
