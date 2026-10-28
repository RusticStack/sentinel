# Developing Sentinel

Run the commands below from the **repository root**. The shared shortcuts live in [`.cargo/config.toml`](../.cargo/config.toml); they use Cargo directly, with no additional task runner or scripting runtime.

## Prerequisites

### All contributors

- Git and rustup. The repository pins Rust 1.97.0 and requests rustfmt/Clippy in `rust-toolchain.toml`; rustup installs missing components when a Cargo command runs.
- A native linker/toolchain: Linux C toolchain and libc development files; Windows Visual Studio Build Tools with the C++ workload and matching Windows SDK.
- Network access for initial toolchain and locked dependency downloads. No GitHub App, cloud account, database service, Node/Deno process, or container engine is required for the Rust lifecycle tests.
- For the web interface only: Node 22+ and pnpm, and Edge, Chrome or Chromium for its browser test ([web interface](web-ui.md)).

See [Rust foundation](rust-foundation.md) for the architecture/target matrix. Use a Linux host or Linux VM for server/worker work. Windows builds the portable CLI; macOS is not supported ([supported platforms](../README.md)). WSL2's filesystem and container isolation do not qualify for executor benchmarks.

### Linux executor work

Prepare a dedicated Linux x86_64 or arm64 environment before running the executor, its tests or its benchmarks:

- Rootless Podman and its distribution-supported OCI runtime, with unprivileged user namespaces enabled.
- A non-root worker account with non-overlapping subordinate UID/GID ranges in `/etc/subuid` and `/etc/subgid`, and the `newuidmap`/`newgidmap` helpers.
- cgroup v2 with CPU/memory controller delegation to that account. Detecting v2 is not enough: check that limits are actually enforced.
- Supported rootless networking and overlay storage helpers for the installed Podman/kernel combination. Keep worker images, workspaces and caches on a local Linux filesystem; do not use a network home or Windows-mounted tree as the performance reference.
- Git, sufficient local disk capacity/inodes, and the standard `kill` executable used by lifecycle tests.

Use the distribution's maintained packages and the [Podman rootless documentation](https://docs.podman.io/en/latest/markdown/podman.1.html). As the intended worker account, inspect:

```sh
podman info --debug
podman unshare cat /proc/self/uid_map /proc/self/gid_map
```

The executor's own tests (`crates/sentinel-worker/tests/podman.rs`, `tests/end_to_end.rs`) run real containers and therefore only as such an account: build them as usual, then run the binaries with `SENTINEL_PODMAN_TESTS=1` from a login shell of the worker account (for example `sudo -iu benchmark env SENTINEL_PODMAN_TESTS=1 <target>/debug/deps/podman-<hash>`); without the variable they print `skipped` and pass nothing. The same holds for every other test file that reads the variable (`grep -rl SENTINEL_PODMAN_TESTS crates`) and for the executor's unit test `executor::tests::a_panicking_attempt_is_torn_down_and_reported` (run the lib's test binary with that filter). `tests/prefetch.rs` also needs the registry: it pulls `hello-world` and `python:3.12-slim` from Docker Hub by digest and removes only those two images, so it can share the account's store with the other suites. The checkout tests need only `git`. The live-controller support (`crates/sentinel-worker/tests/support/live.rs`) force-removes every container carrying its worker's label when it is dropped: a failing test can end while its attempts' threads still run and the process can exit before they tear their containers down, and no later worker start reconciles a test's one-off worker id, so without that cleanup failed runs leave containers behind.

The log path's crash-consistency checks (`tests/crash_consistency.rs`, [logs](logs.md#bounds)) are opt-in too. `SENTINEL_CRASH_TESTS=1` runs the POSIX-strict crash model; it needs `strace` and nothing else (about a minute in a debug build, with scratch in `/dev/shm`). `SENTINEL_POWER_LOSS_TESTS=1` runs the power cuts on ext4 and XFS; it needs root, the `dm-flakey` target (`modprobe dm-flakey`), `losetup`, `dmsetup`, `mkfs.ext4` and `mkfs.xfs`, and takes a few minutes: `sudo env SENTINEL_POWER_LOSS_TESTS=1 cargo test -p sentinel-worker --test crash_consistency -- power_cut_on_dm_flakey --nocapture`.

The benchmark runner records runtime/kernel/filesystem/cgroup details automatically; see [Benchmarking](benchmarking.md) for the baseline. Podman is a worker execution prerequisite, not a dependency for the controller lifecycle or portable CLI.

## Daily checks

The `test-*` commands below run on the verification hosts ([Where tests run](#where-tests-run)); `fmt-check`, `lint` and `release-*` are the local ones. On Linux and Windows:

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

Release output is `target/release/sentinel` (`sentinel.exe` on Windows). CLI and role builds have the same binary name: the most recent build for that profile/target determines the available roles. `release-linux` produces the combined Linux distribution. Setting `CARGO_TARGET_DIR` changes output locations normally. The distributable packages (server, worker, CLI and the static guest agent, with `SHA256SUMS`) are built and checked by `scripts/release/package.sh`, and the server unit by `scripts/release/check-server-unit.sh` ([deployment](deployment.md)).

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

The server answers the API and the worker link; a worker connects only when its configuration names a controller ([configuration](configuration.md#run-the-processes)). Stop each with Ctrl+C; it reports shutdown and exits successfully. Existing directory contents remain. `SIGTERM` and `SIGHUP` also request shutdown; SIGHUP does not reload configuration.

For file-based configuration, copy the appropriate [server](../examples/server.toml) or [worker](../examples/worker.toml) example into `.local/` and supply `--config .local/server.toml` or `--config .local/worker.toml`. Create `.local/` first and set an absolute writable `data_dir`, or override it on the command line. See [configuration](configuration.md) for precedence, size limits, and exit codes.

### Operator first run

A fresh controller has no administrator. Pick one way to create the first:

1. **Web wizard (no shell for the person doing it).** Start the controller (`cargo dev-server --data-dir "$PWD/data/controller"`). Its console prints one `setup_required` line with a token, and the same token is in `data/controller/setup-token` (mode `0600`). Open the web interface, which shows the wizard while setup is open, paste the token, and choose the administrator's address and password, the registration policy (`invite-only` is the default; `approval-required` lets anyone apply; `closed` admits nobody new), whether approved users may create organizations, the instance name and base URL, optionally a first organization, and optionally send a test message through the configured Resend sender (a failed test blocks nothing). The token lives an hour and a restart issues a new one; five wrong guesses lock setup for five minutes. To try email delivery on a development host, put a Resend API key in an owner-only file and start the controller with `SENTINEL_RESEND_API_KEY_FILE=<file> SENTINEL_EMAIL_FROM='Sentinel <you@your-verified-domain>'` (plus `public_url` and a master key); without them the host-local `sentinel admin` commands print the links. Tests never reach Resend: `sentinel-mail`'s `test-endpoint` feature, enabled only by dev-dependencies, points the client at a local scripted server.
2. **CLI.** `printf '%s' "$PASSWORD" | sentinel admin bootstrap --data-dir … --username root`. It closes the same latch and invalidates any open wizard token.

Either way the administrator can then enroll a second factor from the account page, invite people by address, and (under `approved-users`) let approved accounts create their own organizations. [Admission](admission.md#first-run-setup) describes the guarantees; [configuration](configuration.md#first-run-setup-without-a-shell) the files and log line.

### Where tests run

Maintainers run test suites, browser tests and benchmarks on designated Linux verification hosts rather than a workstation or WSL. Local checks are limited to formatting, `cargo check`/lint and `pnpm -C web typecheck`. Host addresses, accounts and keys belong in git-ignored local configuration; [`.env.example`](../.env.example) documents the variable names without providing credentials.

| Host class | Role |
|---|---|
| x86_64 with KVM | Default verification, multi-host controller and microVM tests |
| x86_64 without nested KVM | Same-hardware reference benchmarks and rootless-Podman workers |
| arm64 without nested KVM | arm64 rootless-Podman worker tests |

Use an unprivileged test account with subuid/subgid allocation, systemd user lingering and the permissions required by the test role. KVM tests also need access to `/dev/kvm`. Install the pinned Rust toolchain, `cargo-nextest`, a C toolchain, `pkg-config` and `uidmap`; [`bench/hosts/align-toolchain.sh`](../bench/hosts/align-toolchain.sh) and [`bench/hosts/build-podman.sh`](../bench/hosts/build-podman.sh) describe the aligned container, Node and pnpm toolchain. Browser tests additionally need Chrome for Testing's `chrome-headless-shell`; set `SENTINEL_BROWSER` to its executable or wrapper. There is no Linux arm64 Chrome for Testing build, so browser tests require an x86_64 host.

Run from a disposable checkout on the verification host. Do not use a production checkout or alter production data and services. On a shared host, run under `nice -n 19 ionice -c3`, limit `CARGO_BUILD_JOBS`, check `/proc/pressure/cpu` first and postpone the run when the host is busy. Fault injection must stay inside Sentinel's own processes, network namespaces and loop devices. Stop test processes by PID, never by a command-line pattern.

Benchmarks run only on the host class pinned by their contract. Set `SENTINEL_BENCH_HOST_LABEL` and, when an account label is needed, `SENTINEL_BENCH_USER_LABEL` to stable anonymized values for public records; the harnesses do not capture machine or account names. Record load and CPU pressure with every sample, and never combine measurements from different hosts into one series. A contended host is not a baseline.

The `test-*` aliases use cargo-nextest with `--no-fail-fast`, running every test of every binary in parallel and in separate processes. The workspace has no doctests. `tests/browser.rs` supplies its own libtest-compatible entry point for nextest discovery and filtering.

## Panicking calls in production code

`clippy::unwrap_used` and `clippy::expect_used` are **not** enabled in `[workspace.lints]`: a lint at `warn` fails `cargo lint` (which denies warnings) until every call outside test code is converted, and many are deliberate invariants (a fixed-size slice conversion, a `Mutex` poison, a value checked a line earlier) whose rewrite into error paths would add branches to hot paths for cases that cannot happen. Blanket `#[allow]`s would hide the real decisions. When touching a file, convert a site whose failure is reachable from input; justify each remaining one with `#[expect(clippy::expect_used, reason = "...")]`. List the sites with a search for `.unwrap(` and `.expect(` outside test modules.

## Generated data and credentials

The repository ignores:

| Location | Purpose |
|---|---|
| `target/` | Build output |
| `data/` | Development controller and worker state |
| `.local/` | Local configuration, captures and temporary developer files |
| `.env`, `.env.*` | Local environment files; `.env.example` remains shareable |
| `.cargo/credentials`, `.cargo/credentials.toml` | Accidental repository-local Cargo credential files |
| `*.sqlite`, `*.sqlite-wal`, `*.sqlite-shm` | Runtime metadata and sidecars |

Sentinel does not load dotenv files. Keep actual credentials in an OS credential store or protected files outside the checkout; `.local/` is ignored, not encrypted. Current TOML examples contain only paths. Commit sanitized examples and the lockfile, not generated state or tokens. Use `git status --short` and `git diff --cached --check` before committing; review the staged content as well.

Command verification is recorded in [TODO.md](../TODO.md). See [runtime foundations](runtime-foundation.md) for tracing, IDs, the timing contract and bounded work lanes, [Benchmarking](benchmarking.md) for the no-op runner and its baseline, and the [CI baseline](ci-baseline.md) and [feasibility probes](feasibility-probes.md) for the measured reference.
