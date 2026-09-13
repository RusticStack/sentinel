# Developing Sentinel

Run the commands below from the **repository root**. The shared shortcuts live in [`.cargo/config.toml`](../.cargo/config.toml); they use Cargo directly, with no additional task runner or scripting runtime.

## Prerequisites

### All contributors

- Git and rustup. The repository pins Rust 1.97.0 and requests rustfmt/Clippy in `rust-toolchain.toml`; rustup installs missing components when a Cargo command runs.
- A native linker/toolchain: Linux C toolchain and libc development files; macOS Xcode Command Line Tools; Windows Visual Studio Build Tools with the C++ workload and matching Windows SDK.
- Network access for initial toolchain and locked dependency downloads. No GitHub App, cloud account, database service, Node/Deno process, or container engine is required for the currently implemented lifecycle tests.

See [Rust foundation](rust-foundation.md) for the architecture/target matrix. Use a Linux host or Linux VM for server/worker work. Windows and macOS build the portable CLI. Linux x86_64 WSL2 is verified for the current process/signal tests; that does not qualify its filesystem or container isolation for executor benchmarks.

### Linux executor work (F05/F07 and W03 onward)

Prepare a dedicated Linux x86_64 or arm64 environment before runtime feasibility probes and job execution:

- Rootless Podman and its distribution-supported OCI runtime, with unprivileged user namespaces enabled.
- A non-root worker account with non-overlapping subordinate UID/GID ranges in `/etc/subuid` and `/etc/subgid`, and the `newuidmap`/`newgidmap` helpers.
- cgroup v2 with CPU/memory controller delegation to that account. Verify actual resource enforcement during executor implementation; merely detecting v2 is insufficient.
- Supported rootless networking and overlay storage helpers for the installed Podman/kernel combination. Keep worker images, workspaces and caches on a local Linux filesystem; do not use a network home or Windows-mounted tree as the performance reference.
- Git, sufficient local disk capacity/inodes, and the standard `kill` executable used by lifecycle tests.

Use the distribution's maintained packages and the [Podman rootless documentation](https://docs.podman.io/en/latest/markdown/podman.1.html). As the intended worker account, inspect:

```sh
podman info --debug
podman unshare cat /proc/self/uid_map /proc/self/gid_map
```

Record runtime/kernel/filesystem/cgroup details for F05/F07. No Podman version or host resource budget is qualified yet; those measurements are separate backlog tasks. Podman is a worker execution prerequisite, not a dependency for the controller lifecycle or portable CLI.

## Daily checks

On Linux, macOS, and Windows:

```sh
cargo fmt-check
cargo lint
cargo test-cli
cargo release-cli
```

To apply formatting, run `cargo fmt --all`, then repeat `cargo fmt-check`. All compiling aliases use `--locked`; intentional dependency changes must update and commit `Cargo.lock`.

For Linux role changes, also run:

```sh
cargo lint-linux
cargo test-server
cargo test-worker
cargo test-linux
cargo release-linux
```

The role tests cover each feature independently and together, including unavailable-role errors in single-role builds. `test-cli` runs with default features, which currently exclude both roles. `--all-targets` in the lint aliases checks package tests/examples as well as the binary; it does not cross-compile for every operating system. Cross-target checks are documented in [Rust foundation](rust-foundation.md).

Each command returns Cargo's exit status. Stop and fix failures before proceeding. There is no aggregate alias hiding intermediate failures. Extra test arguments can be appended, for example `cargo test-linux -- --nocapture`.

Release output is `target/release/sentinel` (`sentinel.exe` on Windows). CLI and role builds have the same binary name: the most recent build for that profile/target determines the available roles. `release-linux` produces the combined Linux distribution. Setting `CARGO_TARGET_DIR` changes output locations normally.

## Local two-process workflow

Open two Linux terminals at the repository root. Use separate writable directories, with no elevated privileges:

```sh
cargo dev-server --data-dir "$PWD/data/controller" --check
cargo dev-worker --data-dir "$PWD/data/worker" --check
```

These validate configuration without creating state. Then, in terminal one:

```sh
cargo dev-server --data-dir "$PWD/data/controller"
```

In terminal two:

```sh
cargo dev-worker --data-dir "$PWD/data/worker"
```

The aliases already contain Cargo's `--` separator; append Sentinel arguments directly. Each alias selects its own role feature explicitly. Initial builds may briefly wait on Cargo's build lock; the running process does not retain that lock. Configuration and startup output identify the role and resolved path.

Both processes currently initialize their directories and wait for shutdown. They do not connect, accept jobs or expose an API. Stop each with Ctrl+C; it reports shutdown and exits successfully. Existing directory contents remain. `SIGTERM` and `SIGHUP` also request shutdown; SIGHUP does not reload configuration.

For file-based configuration, copy the appropriate [server](../examples/server.toml) or [worker](../examples/worker.toml) example into `.local/` and supply `--config .local/server.toml` or `--config .local/worker.toml`. Create `.local/` first and set an absolute writable `data_dir`, or override it on the command line. See [configuration](configuration.md) for precedence, size limits, and exit codes.

### Windows with WSL2

Run the Linux commands inside the Linux distribution, with Linux Rust/linker prerequisites installed. A checkout in the Linux filesystem is preferred. If sharing this Windows checkout through `/mnt/...`, set `export CARGO_TARGET_DIR=target/wsl` in both Linux terminals to keep native Windows and WSL build outputs separate. Current lifecycle checks can run this way; use a native Linux filesystem and identified hardware for cache/I/O benchmarks.

## Generated data and credentials

The repository ignores:

| Location | Purpose |
|---|---|
| `target/` | Native/cross/WSL build output |
| `data/` | Development controller and worker state |
| `.local/` | Local configuration, captures and temporary developer files |
| `.env`, `.env.*` | Local environment files; `.env.example` remains shareable |
| `.cargo/credentials`, `.cargo/credentials.toml` | Accidental repository-local Cargo credential files |
| `*.sqlite`, `*.sqlite-wal`, `*.sqlite-shm` | Runtime metadata and sidecars |

Sentinel does not load dotenv files. Keep actual credentials in an OS credential store or protected files outside the checkout; `.local/` is ignored, not encrypted. Current TOML examples contain only paths. Commit sanitized examples and the lockfile, not generated state or tokens. Use `git status --short` and `git diff --cached --check` before committing; review the staged content as well.

F03's command verification is recorded in [TODO.md](../TODO.md). Performance measurement, structured tracing, and runtime isolation qualification remain F04–F07 and later work.
