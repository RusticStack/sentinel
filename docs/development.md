# Developing Sentinel

Run the commands below from the **repository root**. The shared shortcuts live in [`.cargo/config.toml`](../.cargo/config.toml); they use Cargo directly, with no additional task runner or scripting runtime.

## Prerequisites

### All contributors

- Git and rustup. The repository pins Rust 1.97.0 and requests rustfmt/Clippy in `rust-toolchain.toml`; rustup installs missing components when a Cargo command runs.
- A native linker/toolchain: Linux C toolchain and libc development files; Windows Visual Studio Build Tools with the C++ workload and matching Windows SDK.
- Network access for initial toolchain and locked dependency downloads. No GitHub App, cloud account, database service, Node/Deno process, or container engine is required for the Rust lifecycle tests.
- For the web interface only: Node 22+ and pnpm, and Edge, Chrome or Chromium for its browser test ([web interface](web-ui.md)).

See [Rust foundation](rust-foundation.md) for the architecture/target matrix. Use a Linux host or Linux VM for server/worker work. Windows builds the portable CLI; macOS is not supported ([supported platforms](../README.md)). Linux x86_64 WSL2 is verified for the current process/signal tests; that does not qualify its filesystem or container isolation for executor benchmarks.

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

The executor's own tests (`crates/sentinel-worker/tests/podman.rs`, `tests/end_to_end.rs`) run real containers and therefore only as such an account: build them as usual, then run the binaries with `SENTINEL_PODMAN_TESTS=1` from a login shell of the worker account (for example `sudo -iu sentinelbench env SENTINEL_PODMAN_TESTS=1 <target>/debug/deps/podman-<hash>`); without the variable they print `skipped` and pass nothing. The same holds for `tests/executor_faults.rs`, `tests/compiler_cache.rs`, `tests/k09.rs`, `tests/slice.rs` and the executor's unit test `executor::tests::a_panicking_attempt_is_torn_down_and_reported` (run the lib's test binary with that filter). `tests/prefetch.rs` (K05) also needs the registry: it pulls `hello-world` and `python:3.12-slim` from Docker Hub by digest and removes only those two images, so it can share the account's store with the other suites. The checkout tests need only `git`.

The log path's crash-consistency checks (`tests/crash_consistency.rs`, [logs](logs.md#bounds)) are opt-in too. `SENTINEL_CRASH_TESTS=1` runs the POSIX-strict crash model; it needs `strace` and nothing else (about a minute in a debug build, with scratch in `/dev/shm`). `SENTINEL_POWER_LOSS_TESTS=1` runs the power cuts on ext4 and XFS; it needs root, the `dm-flakey` target (`modprobe dm-flakey`; the WSL2 kernel ships it), `losetup`, `dmsetup`, `mkfs.ext4` and `mkfs.xfs`, and takes a few minutes: `sudo env SENTINEL_POWER_LOSS_TESTS=1 cargo test -p sentinel-worker --test crash_consistency -- power_cut_on_dm_flakey --nocapture`.

The benchmark runner records runtime/kernel/filesystem/cgroup details automatically; see [Benchmarking](benchmarking.md) for the F05 baseline. No host resource budget is qualified yet. Podman is a worker execution prerequisite, not a dependency for the controller lifecycle or portable CLI.

## Daily checks

On Linux and Windows:

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

`cargo run -p sentinel -- pipeline validate <file>` and `pipeline explain <file> [--json]` check a `.sentinel.yml` offline on any platform (see [pipeline schema](pipeline-schema.md#bindings-and-offline-validation-c07)). `cargo bench-noop --help` runs the benchmark runner in release mode; see [Benchmarking](benchmarking.md). `cargo probe --help` runs the feasibility probes; see [feasibility probes](feasibility-probes.md).

The role tests cover each feature independently and together, including unavailable-role errors in single-role builds. `test-cli` runs with default features, which currently exclude both roles. `--all-targets` in the lint aliases checks package tests/examples as well as the binary; it does not cross-compile for every operating system. Cross-target checks are documented in [Rust foundation](rust-foundation.md).

For web interface changes (`web/`):

```sh
pnpm -C web install --frozen-lockfile
pnpm -C web typecheck
pnpm -C web build
cargo test -p sentinel-api --test web_browser -- --ignored --nocapture the_web_interface
```

The browser test starts a seeded controller and the built interface; `serve_the_fixture` (same test binary) serves them for a person to look at (`SENTINEL_SERVE_SECS`, default 600). For live editing, run `pnpm -C web dev` with `NUXT_SENTINEL_API` pointing at a controller (or at a running `sentinel-web`, which proxies the API); sign in on the origin the controller names as `public_url`, whose session cookie the dev server shares (cookies ignore the port).

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

### Where tests run

Every test — a single test binary, the full `test-*` suites, the web browser test and benchmarks — runs on the verification VPS, never on a workstation or in WSL (the owner's decision of 2026-09-27: local runs exhaust memory and wear the disk). The host, user and SSH key are in the git-ignored `.env` at the repository root; [`.env.example`](../.env.example) names the variables. Local work stops at `cargo fmt`, `cargo check`/`cargo lint` and `pnpm -C web typecheck`.

Ship the branch as a git bundle (or push it) and run there, as root or the test account, from a checkout on the VPS's own filesystem. The VPS is shared with production services and another project's CI: run under `nice -n 19 ionice -c3` with `CARGO_BUILD_JOBS` limited, check `/proc/pressure/cpu` first, and when the host is heavily loaded skip the run and record the verification as pending. Record the load (`uptime`, CPU pressure) with every benchmark; a contended host is not a baseline.

What is installed there (2026-09-27, Ubuntu 26.04, 12 vCPU EPYC, 31 GiB):

| For | Installed |
|---|---|
| Rust suites | `build-essential`, `pkg-config`, rustup for root with the pinned 1.97.0 (clippy, rustfmt) |
| Checkout | `/srv/sentinel`, world-readable; run logs, load snapshots and scripts in `/srv/sentinel-runs` |
| Web interface and browser test | Ubuntu's `nodejs` (22) and `npm`, `pnpm` 10 (npm global), Chrome for Testing's `chrome-headless-shell` in `/opt/chrome-headless-shell` — Ubuntu ships Chromium only as a snap, whose private `/tmp` does not see the test's profile directory |
| Executor tests and benchmarks | `podman` 5.7 (rootless, runc, overlay, cgroup v2), `uidmap`, `slirp4netns`; the `sentinelbench` account (subuid/subgid, lingering, `safe.directory` for `/srv/sentinel`) |

Chrome refuses to run as root without `--no-sandbox`; `/opt/chrome-headless-shell/as-root` adds it, so a root run passes `SENTINEL_BROWSER=/opt/chrome-headless-shell/as-root`. Run the suites with `--no-fail-fast` so one pass reports every failing binary. Another project's CI runs `cargo test` on the same host: stop your own processes by PID, never by a pattern such as `pkill -f "cargo test"`.

### Windows with WSL2 (superseded)

Not used for tests any more (see above). Kept for reference:


Run the Linux commands inside the Linux distribution, with Linux Rust/linker prerequisites installed, from a checkout in the Linux filesystem — for example `/srv/sentinel`, world-readable so the rootless-Podman test account can run the built test binaries. A Windows checkout shared through `/mnt/...` is not suitable: that filesystem does not keep Unix permissions, so the owner-only file checks fail. Use a native Linux filesystem and identified hardware for cache/I/O benchmarks.

**Testing on the storage users run.** Operators commonly run Sentinel on spinning disks, so test on one when the machine has it: put the Windows checkout (and so its `target/`) on that drive, and point test temp directories there with a machine-local Cargo config *outside* the repository, for example `E:\Projects\.cargo\config.toml`:

```toml
[env]
TMP = { value = 'E:\Projects\.tmp', force = true }
TEMP = { value = 'E:\Projects\.tmp', force = true }
```

`force` is needed because every Windows shell already sets `TMP`/`TEMP`; the temp directory must sit outside every Git work tree, since the CLI refuses a configuration directory inside one. For Linux, place the WSL distribution on the same drive (`wsl --manage <distro> --move <dir>`) so the Linux checkout, its `target/` and `/tmp` live there too.

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

Command verification is recorded in [TODO.md](../TODO.md). See [runtime foundations](runtime-foundation.md) for F04's tracing, IDs, timing contract and bounded work lanes. The no-op benchmark runner and its baseline are described in [Benchmarking](benchmarking.md); The measured [CI baseline](ci-baseline.md) and [feasibility probes](feasibility-probes.md) complete Part 01; production-host qualification repeats them on dedicated hardware.
