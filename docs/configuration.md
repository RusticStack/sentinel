# CLI and process configuration

F02 implements the server and worker **process lifecycle**: command parsing, configuration validation, data-directory initialization, and clean signal-driven exit. F04 adds structured diagnostics, monotonic timing and bounded execution lanes; see [runtime foundations](runtime-foundation.md). Scheduling, API listeners, worker enrollment/connections, job execution, and durable writers arrive in later tasks. Startup explicitly reports this lifecycle-only status.

## Build and inspect

For shared Cargo shortcuts and contributor prerequisites, see [Development](development.md).

```sh
cargo build --locked --release --features server,worker
./target/release/sentinel --version
./target/release/sentinel --help
./target/release/sentinel server --help
./target/release/sentinel worker --help
```

The role build command requires Linux. Portable CLI builds use `cargo build --locked --release` and support help/version on Linux/macOS/Windows. Requesting a role omitted from the build produces an explicit unavailable-role error. Help describes both roles even in CLI-only builds; it does not indicate role availability. No command defaults to starting a service.

`--version` (also accepted after the subcommand) reports the package version from Cargo metadata. The current version is a development version, not a released executor.

## Configuration contract

Each role accepts:

| Option | Behavior |
|---|---|
| `--config FILE` | Read this UTF-8 TOML file; relative file paths resolve from the working directory |
| `--data-dir PATH` | Override the data directory; must be absolute |
| `--check` | Validate and print the effective data directory, then exit without creating directories, installing signal handlers or starting the lifecycle |
| `--log-format text\|json` | Internal diagnostic format; defaults to `text` |
| `--log-level error\|warn\|info\|debug\|trace` | Diagnostic verbosity; defaults to `info` |

Precedence is **built-in role defaults < explicit config file < command-line flags**. There is no implicit config discovery, environment-variable override, shell expansion, or dotenv loading. A supplied configuration file must be valid even when a flag overrides a setting.

The complete current file schema is:

```toml
data_dir = "/srv/sentinel/controller"
log_format = "text"
log_level = "info"
# server only: where workers connect (default 127.0.0.1:7443) and where the API answers (default 127.0.0.1:7080)
listen = "0.0.0.0:7443"
api_listen = "127.0.0.1:7080"
# worker only: the controller to reach and the fingerprint it logged at `link_listening`
controller = "10.0.0.5:7443"
controller_fingerprint = "<64 lower-case hex characters>"
worker_name = "builder-1"          # 1-128 bytes, default "worker"
enrollment_file = "/etc/sentinel/enrollment"  # absolute; read on start, removed once spent
cpu_millis = 8000                  # override measured capacity (default: every core)
memory_bytes = 34359738368         # override measured capacity (default: total less a host reserve)
```

The three common fields are optional in the file; `listen` and `api_listen` are refused for the worker and the worker keys for the server; `controller` and `controller_fingerprint` are set together or not at all, and the other worker keys need them. A worker without a controller configured idles as a lifecycle-only process. Empty files use the logging defaults above and the role data path:

- Server: `/var/lib/sentinel`
- Worker: `/var/lib/sentinel-worker`

Use separate directories for the two roles. Paths must be absolute, non-root, and contain no `..` components. An existing non-directory is rejected. Existing directory contents are preserved. Data directories are trusted operator-managed paths; F02 does not provide an artifact extraction sandbox or a single-process directory lease. Ownership and access permissions follow the service account and its umask; Sentinel does not elevate privileges or change ownership.

Configuration input must be a regular file, valid UTF-8, and at most **64 KiB**. Unknown/duplicate keys, wrong field types and malformed TOML fail validation. Parser failures report the expected schema without echoing input values. There are no credential fields in this schema; enrollment credentials have a separate interface, and source credentials are sealed in the database.

Two optional controller files configure sources ([sources](sources.md)) and event intake ([intake](intake.md)); both are read at startup when present:

- `<data_dir>/source-destinations.json` — a JSON array of at most 128 approved authorities (`https://host[:port]`, `ssh://user@host[:port]`). A source binding whose remote is not exactly one of them is refused. Absent means no binding can be created.
- `<data_dir>/github-app.json` — `{"app_id": 1234, "private_key_file": "/absolute/owner-only.pem"}` for the GitHub App association. The PEM must be a regular file, not group- or world-readable, at most 16 KiB, PKCS#1 or unencrypted PKCS#8. The App key is never stored in the database.
- `<data_dir>/github-webhook.json` — `{"secret": "…"}` for GitHub webhook signature verification; the secret is 16–256 printable ASCII bytes and the file must be owner-only. Without it the GitHub intake route does not exist.

Source credentials themselves are sealed with `<data_dir>/master.key` (`admin key create`), the same key-outside-database file second factors use. Repository hook secrets are digests and need no key. Resolution also uses `<data_dir>/intake-work/` as per-delivery scratch space for the repository fetches it makes; it is emptied at startup and never reused.

`--check` validates syntax, effective path shape and currently inspectable filesystem metadata. It does not prove future write access, reserve the directory or validate networking/runtime prerequisites. Actual startup creates missing directories and reports initialization failures.

## Run the processes

On Linux, use independent terminals and writable absolute paths:

```sh
./target/release/sentinel server --data-dir "$PWD/data/controller" --check
./target/release/sentinel worker --data-dir "$PWD/data/worker" --check
```

Start the controller in one terminal:

```sh
./target/release/sentinel server --data-dir "$PWD/data/controller"
```

Start the worker in another:

```sh
./target/release/sentinel worker --data-dir "$PWD/data/worker"
```

Alternatively use `--config examples/server.toml` or `--config examples/worker.toml`, overriding `--data-dir` for a development account. The server process never starts the worker process. The server listens for workers on `listen` and logs `link_listening` with the address and the fingerprint workers pin, and answers the [API](api.md) on `api_listen` (`api_listening`); a worker with `controller`/`controller_fingerprint` configured connects, enrolls on its first hello with the secret in `enrollment_file`, and reconnects with back-off thereafter. See [worker link](worker-link.md#processes). The worker runs jobs only with rootless Podman on cgroup v2 available to its account ([development](development.md#linux-executor-work-f05f07-and-w03-onward)); it logs `executor_ready` with the runtime, or `executor_unavailable` and declines offers.

## Host-local administration

`sentinel admin` acts on the controller's own host, against `<data_dir>/metadata.sqlite`. Its authority is filesystem access to that database, not a session, and it is built into the Linux `server` binary only.

```sh
printf '%s' "$OPERATOR_PASSWORD" | ./target/release/sentinel admin bootstrap     --data-dir "$PWD/data/controller" --username root --display-name "Root Operator"
./target/release/sentinel admin status --data-dir "$PWD/data/controller"
printf '%s' "$NEW_PASSWORD" | ./target/release/sentinel admin recover     --data-dir "$PWD/data/controller" --username root
```

Scoped, expiring API credentials are provisioned the same way, and the secret is the only thing written to stdout:

```sh
./target/release/sentinel admin token issue --data-dir "$PWD/data/controller" \
    --user root --name "laptop cli" --scope read,run --expires-in 7d > credential
./target/release/sentinel admin token list --data-dir "$PWD/data/controller" --user root
./target/release/sentinel admin token revoke --data-dir "$PWD/data/controller" --id tok_...
```

Passwords are read from standard input only; no subcommand accepts one in argv, and a terminal stdin is refused. `bootstrap` creates the database if needed and is refused once any active super admin exists; `status` and `recover` refuse a path with no database rather than creating an empty one. Exit code 2 covers every refusal. Linked external sign-in identities are inspected with `admin identity list` and removed with `admin identity unlink`; linking itself only follows a verified provider sign-in. `admin policy`, `admin invite` and `admin account` show and change the deployment's admission policy, issue and revoke one-time invitations, and decide pending applications. `admin key create` writes the owner-only `master.key` that seals second-factor seeds; `admin mfa` and `admin session` inspect and remove an account's second factor and sessions. `admin tenant` creates, suspends and reactivates a namespace; `admin pool` registers pools and grants shared ones to tenants; `admin worker` issues one-time enrollments, lists and revokes workers; `admin source create|bind|show|revoke|hook-token|refresh-installation|bind-installation|remove-installation` binds repositories to approved remotes with sealed credentials, issues the repository's intake hook secret and manages GitHub App installations ([sources](sources.md), [intake](intake.md)); `admin intake list|purge` shows and retires durable event deliveries; `admin logs --attempt att_… [--follow]` prints an attempt's log from `<data_dir>/logs` ([logs](logs.md)); `admin cancel --job job_…|--run run_…` records cancellation ([cancellation](cancellation.md)). Admin commands open the database directly, so they run beside a **stopped** server — one controller owns the database; while it runs, use the [API](api.md) and `sentinel api …` instead. See [local authentication](local-authentication.md), [API credentials](api-credentials.md) [GitHub sign-in](github-sign-in.md) and [admission](admission.md), [step-up](step-up.md), [tenancy](tenancy.md) and [worker link](worker-link.md).

## Shutdown and output

- Ctrl+C / `SIGINT`, service-manager `SIGTERM`, and `SIGHUP` request a clean exit. SIGHUP is **shutdown**, not configuration reload.
- A handler is registered before directory initialization. A capacity-one notification channel retains a shutdown request during startup and coalesces repeated requests; the main thread blocks without polling while idle.
- Structured startup and lifecycle diagnostics go to stderr. Help, version and successful `--check` output go to stdout. Bootstrap CLI/configuration errors remain plaintext.
- The main thread closes the bounded I/O/CPU lanes (one second per lane) and drains internal diagnostics (500 ms). Incomplete lane shutdown or diagnostic sink failure returns exit code 1. The server then closes worker sessions and stops the dispatcher (2 s) and drains the metadata store (5 s; a stall is reported and exits 1, and the store keeps database ownership until the process exits). The worker closes its session from the shutdown thread, so no heartbeat has to elapse. Nothing executes yet (W03), so there are no jobs to cancel; leases and offers are rows the next start reconciles.
- Data directories and existing contents survive shutdown. Uncatchable termination such as SIGKILL cannot run cleanup.

| Exit code | Meaning |
|---|---|
| `0` | Help/version/check succeeded, or requested lifecycle shutdown completed |
| `1` | Runtime initialization, bootstrap task deadline, lifecycle failure or incomplete diagnostic drain |
| `2` | CLI usage error, unavailable role, or invalid/unreadable configuration |

## Verification

The integration tests invoke the actual executable. On Linux with role features, they check configuration precedence, no-write checks, malformed/oversized input, path validation, and each enabled role's initialization/clean exit under all three supported signals. They use temporary directories and bounded waits for lifecycle assertions. Linux tests require the standard `kill` command; they do not need Podman, GitHub, root, or network services.

```sh
cargo test --locked --workspace
cargo test --locked --workspace --features server
cargo test --locked --workspace --features worker
cargo test --locked --workspace --features server,worker
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

Only the first test command applies to non-Linux builds. See [Rust foundation](rust-foundation.md) for the cross-target build contract and dependency boundaries.
