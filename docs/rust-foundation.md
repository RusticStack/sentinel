# Rust workspace and platform contract

Implemented for **F01**, updated through **F04**. The repository builds a `sentinel` executable with help/version, typed role configuration, Linux process startup/shutdown, and [tracing/timing/work-lane foundations](runtime-foundation.md). See [CLI and configuration](configuration.md). Job execution and GitHub integration are not implemented yet.

## Workspace

```text
Cargo.toml                    workspace, shared package metadata and lint policy
Cargo.lock                    committed dependency resolution
rust-toolchain.toml           exact compiler/tooling pin
crates/sentinel/Cargo.toml     initial executable package and role features
crates/sentinel/src/main.rs    platform guard and role dispatch
crates/sentinel/src/cli.rs     portable command definitions
crates/sentinel/src/service.rs Linux configuration and process lifecycle
crates/sentinel/src/lib.rs     shared options and Linux foundation modules
crates/sentinel/tests/cli.rs   executable-level contract tests
```

One package is sufficient for the foundation. Introduce library modules/crates when implemented boundaries justify them; avoid empty server/store/scheduler crates. The executable includes feature-gated server and worker lifecycles on Linux, with each role running as a separate process.

The package is `0.1.0-dev`, MIT, and not published to crates.io. This version identifies development code, not a released CI engine.

## Toolchain and build policy

- Pin **Rust 1.97.0**, including Cargo, with the minimal rustup profile plus rustfmt and Clippy. It is the compiler verified for this foundation, not a claim about the latest upstream release.
- Use edition **2024** and workspace resolver **3**. Declare `rust-version = "1.97"`; an older minimum compiler has not been qualified. Keep the manifest floor and the exact toolchain pin consistent when upgrading.
- Commit `Cargo.lock` because Sentinel is an application; use `--locked` for reproducible dependency resolution. Compiler/lockfile pins do not alone guarantee bit-for-bit builds across different host SDKs/linkers.
- Do not set a global compilation target or `target-cpu=native`: developers build on their host by default, and portable release artifacts must not accidentally require the build machine's CPU features.
- Keep Cargo's standard development/release profiles initially. LTO, allocator, panic strategy, codegen and CPU tuning need benchmark evidence rather than speculative F01 settings.
- Inherit the workspace lint that denies implicit unsafe operations inside unsafe functions. No unsafe code is present. Future unsafe optimizations need localized explicit operations and documented invariants; dependencies are not rewritten to avoid their maintained implementations.

## Platform and feature matrix

Features select which **roles can be compiled**, not user authorization or paid capabilities. They enable Linux lifecycle commands and their configuration/signal dependencies.

| Target triple | Build contract | Features |
|---|---|---|
| `x86_64-unknown-linux-gnu` | Linux x86_64 CLI, server, worker | default CLI; `server`, `worker`, or both |
| `aarch64-unknown-linux-gnu` | Linux arm64 CLI, server, worker | default CLI; `server`, `worker`, or both |
| `x86_64-apple-darwin` | macOS Intel CLI | default / no role features |
| `aarch64-apple-darwin` | macOS Apple silicon CLI | default / no role features |
| `x86_64-pc-windows-msvc` | Windows x86_64 CLI | default / no role features |
| `aarch64-pc-windows-msvc` | Windows arm64 CLI | default / no role features |

`server` and `worker` are additive, opt-in features. A Linux distribution can contain both; CLI-only builds carry neither. Enabling either on a non-Linux target fails compilation with an explicit diagnostic. Later role modules/dependencies must follow the same feature/platform boundary. CLI-only builds must remain free of container-execution/server dependencies.

GNU Linux targets are the initial Linux contract. Musl/static distribution, additional operating systems/architectures, native installers and minimum OS/libc versions require subsequent qualification; no global linker/sysroot configuration is baked into this workspace.

### Native build

With rustup and the platform's native linker prerequisites installed:

```sh
cargo build --locked
cargo build --locked --release
```

On Linux, compile the complete role distribution:

```sh
cargo build --locked --release --features server,worker
```

Run `sentinel --help` or `sentinel --version` to inspect the build. F02 replaced F01's status-only executable with command entry points; see [configuration](configuration.md) for startup and exit semantics.

### Target checks

Install only the cross-target standard libraries needed for your work; cloning the repository must not automatically download every platform:

```sh
rustup target add --toolchain 1.97.0 x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
rustup target add --toolchain 1.97.0 x86_64-apple-darwin aarch64-apple-darwin
rustup target add --toolchain 1.97.0 x86_64-pc-windows-msvc aarch64-pc-windows-msvc
```

Validate the target/role combinations without requiring cross-linkers:

```sh
cargo check --locked --workspace --all-targets --target x86_64-unknown-linux-gnu --features server,worker
cargo check --locked --workspace --all-targets --target aarch64-unknown-linux-gnu --features server,worker
cargo check --locked --workspace --all-targets --target x86_64-apple-darwin
cargo check --locked --workspace --all-targets --target aarch64-apple-darwin
cargo check --locked --workspace --all-targets --target x86_64-pc-windows-msvc
cargo check --locked --workspace --all-targets --target aarch64-pc-windows-msvc
```

Also check `server` and `worker` individually on Linux, and verify each is rejected on macOS/Windows. `--all-targets` means package binaries/tests/examples/benches for the selected platform; it does not iterate all operating systems. `--all-features` is appropriate for Linux, but intentionally invalid on non-Linux hosts because it enables Linux-only roles.

`cargo check` verifies Rust compilation/type checking, **not native linking or runtime behavior**. Windows MSVC builds need the appropriate Visual C++ linker/SDK; Linux builds need a compatible native/cross linker and libc; macOS binaries require an Apple SDK/toolchain. Release qualification will build/run on the actual supported systems. Container runtime conformance remains a later Linux executor task.

## Library and dependency boundaries

| Category | Current choice | Boundary for subsequent work |
|---|---|---|
| Portable CLI | `clap` derive with std/help/usage/error-context; default features disabled | Parsing/help/version on all supported CLI targets; no server runtime dependencies |
| Linux role configuration | Optional `serde` derive and `toml` with only std/parse/serde | Compiled only with server or worker on Linux; strict bounded file input |
| Linux signal handling | Optional `ctrlc` with termination feature | SIGINT/SIGTERM/SIGHUP delivered to a bounded main-thread notification channel; no Tokio runtime needed for this lifecycle |
| Linux diagnostics/IDs | Optional `tracing` (std only), `tracing-subscriber` (std/fmt/json/registry, defaults off), and `uuid` v4 | Structured events and explicit context propagation; bounded stderr queue; typed random correlation IDs. No network exporter or tracing environment filter |
| Build dependencies / build scripts | None | No network/tool installers or opaque code generation during builds; add only for a concrete documented need |
| Development dependencies | `tempfile` for isolated process-test data and `serde_json` for output assertions | Test-only direct dependencies; JSON serialization also enters Linux role builds transitively through the subscriber |
| Development tooling | Pinned Cargo, rustfmt, Clippy | Toolchain components, not services installed in production |
| OS/runtime prerequisites | Native linker/SDK for linking | Git and rootless Podman are future Linux worker runtime tools, not server/CLI dependencies |
| UI toolchain | Not selected or installed | Future build-time tooling produces embedded static assets; no required Node/Deno server |
| Networking, SQLite, TLS, crypto | Not added yet | Select maintained libraries at the implementing task; use bounded APIs and avoid unnecessary default features |
| Optional Tailcat / S3 | No helper or SDK dependency yet | Add only with the implemented transport/storage feature; no mandatory external service |

There is intentionally no empty `[workspace.dependencies]` catalog or speculative dependency stack. F01 used only the standard library; later tasks add the above libraries for implemented behavior. Exact versions, including proc-macro and platform transitive dependencies, are committed in `Cargo.lock`. Sentinel has no build script or direct build dependencies; maintained dependencies may use build scripts and proc macros. Inspect `cargo tree --locked --edges normal,build` with the selected target/features to distinguish the actual production tree from dev-only and inactive lockfile packages. Work lanes and bounded queue plumbing use the standard library; no async runtime is introduced before a networking/control-loop requirement exists.

## Foundation verification

The F01/F02 completion records in [TODO.md](../TODO.md) record executed checks and platform limits. Relevant portable checks are:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release
cargo metadata --locked --no-deps --format-version 1
cargo tree --locked
```

F02 adds meaningful command/configuration and real Linux signal-lifecycle integration tests. Run the feature-specific Linux commands in [configuration](configuration.md) in addition to portable checks; non-Linux builds cannot enable role features.

Cargo reference used for workspace inheritance, resolver and lint configuration: [Cargo workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html) and [feature resolver](https://doc.rust-lang.org/cargo/reference/resolver.html). Verification is against the pinned toolchain, not documentation assumptions alone.
