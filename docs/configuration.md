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
```

All three fields are optional in the file. Empty files use the logging defaults above and the role data path:

- Server: `/var/lib/sentinel`
- Worker: `/var/lib/sentinel-worker`

Use separate directories for the two roles. Paths must be absolute, non-root, and contain no `..` components. An existing non-directory is rejected. Existing directory contents are preserved. Data directories are trusted operator-managed paths; F02 does not provide an artifact extraction sandbox or a single-process directory lease. Ownership and access permissions follow the service account and its umask; Sentinel does not elevate privileges or change ownership.

Configuration input must be a regular file, valid UTF-8, and at most **64 KiB**. Unknown/duplicate keys, wrong field types and malformed TOML fail validation. Parser failures report the expected schema without echoing input values. There are no credential fields in this schema; secrets and enrollment credentials will have separately defined interfaces.

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

Alternatively use `--config examples/server.toml` or `--config examples/worker.toml`, overriding `--data-dir` for a development account. The server process never starts the worker process. These processes currently have no network connection to one another.

## Shutdown and output

- Ctrl+C / `SIGINT`, service-manager `SIGTERM`, and `SIGHUP` request a clean exit. SIGHUP is **shutdown**, not configuration reload.
- A handler is registered before directory initialization. A capacity-one notification channel retains a shutdown request during startup and coalesces repeated requests; the main thread blocks without polling while idle.
- Structured startup and lifecycle diagnostics go to stderr. Help, version and successful `--check` output go to stdout. Bootstrap CLI/configuration errors remain plaintext.
- The main thread closes the bounded I/O/CPU lanes (one second per lane) and drains internal diagnostics (500 ms). Incomplete lane shutdown or diagnostic sink failure returns exit code 1. There are currently no jobs, durable writers or sockets to drain. Future subsystems must add bounded cancellation/drain/flush before reporting stopped; current lifecycle shutdown is not evidence of durable job shutdown.
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
