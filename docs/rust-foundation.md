# Rust workspace and platform contract

The repository builds one `sentinel` executable with help/version, typed role configuration, Linux process startup/shutdown and [tracing/timing/work-lane foundations](runtime-foundation.md). See [CLI and configuration](configuration.md); job execution is in the [executor](executor.md).

## Workspace

```text
Cargo.toml                    workspace, shared package metadata and lint policy
Cargo.lock                    committed dependency resolution
rust-toolchain.toml           exact compiler/tooling pin
crates/sentinel/              the executable: CLI, role lifecycles, role features
crates/sentinel-*/            libraries by boundary (store, api, link, worker, s3, ...)
```

The executable includes feature-gated server and worker lifecycles on Linux, with each role running as a separate process. Add crates only when an implemented boundary justifies them; avoid empty crates.

The package is `0.1.0-dev`, MIT, and not published to crates.io.

## Toolchain and build policy

- Pin **Rust 1.97.0**, including Cargo, with the minimal rustup profile plus rustfmt and Clippy. 
- Use edition **2024** and workspace resolver **3**. Declare `rust-version = "1.97"`; an older compiler is not qualified. Keep the manifest floor and the exact toolchain pin consistent when upgrading.
- Commit `Cargo.lock` because Sentinel is an application; use `--locked` for reproducible dependency resolution. Compiler/lockfile pins do not alone guarantee bit-for-bit builds across different host SDKs/linkers.
- Do not set a global compilation target or `target-cpu=native`: developers build on their host by default, and portable release artifacts must not accidentally require the build machine's CPU features.
- Keep Cargo's standard development/release profiles initially. LTO, allocator, panic strategy, codegen and CPU tuning need benchmark evidence.
- Inherit the workspace lint that denies implicit unsafe operations inside unsafe functions. Every `unsafe` block needs a `// SAFETY:` comment stating its invariant ([AGENTS.md](../AGENTS.md)); dependencies are not rewritten to avoid their maintained implementations.

## Platform and feature matrix

Features select which **roles can be compiled**, not user authorization or paid capabilities. They enable Linux lifecycle commands and their configuration/signal dependencies.

| Target triple | Build contract | Features |
|---|---|---|
| `x86_64-unknown-linux-gnu` | Linux x86_64 CLI, server, worker | default CLI; `server`, `worker`, or both |
| `aarch64-unknown-linux-gnu` | Linux arm64 CLI, server, worker | default CLI; `server`, `worker`, or both |
| `x86_64-pc-windows-msvc` | Windows x86_64 CLI | default / no role features |
| `aarch64-pc-windows-msvc` | Windows arm64 CLI | default / no role features |

`server` and `worker` are additive, opt-in features. A Linux distribution can contain both; CLI-only builds carry neither. Enabling either on a non-Linux target fails compilation with an explicit diagnostic. Role modules and dependencies follow the same feature/platform boundary: CLI-only builds stay free of container-execution and server dependencies.

These four targets are the whole platform contract; the [README](../README.md) states it in one line. macOS was dropped by decision on 2026-09-24: there is no macOS build target, credential store or browser path. **Linux is the only supported Unix.** Code gated `cfg(unix)` is written for Linux, and Linux-specific calls sit under `cfg(target_os = "linux")` with a portable fallback, so another Unix target may still compile, but it is not built, tested or supported, and no `compile_error!` guards it.

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

Run `sentinel --help` or `sentinel --version` to inspect the build; see [configuration](configuration.md) for startup and exit semantics.

### Target checks

Install only the cross-target standard libraries needed for your work; cloning the repository must not automatically download every platform:

```sh
rustup target add --toolchain 1.97.0 x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
rustup target add --toolchain 1.97.0 x86_64-pc-windows-msvc aarch64-pc-windows-msvc
```

Validate the target/role combinations without requiring cross-linkers:

```sh
cargo check --locked --workspace --all-targets --target x86_64-unknown-linux-gnu --features server,worker
cargo check --locked --workspace --all-targets --target aarch64-unknown-linux-gnu --features server,worker
cargo check --locked --workspace --all-targets --target x86_64-pc-windows-msvc
cargo check --locked --workspace --all-targets --target aarch64-pc-windows-msvc
```

Also check `server` and `worker` individually on Linux, and verify each is rejected on Windows. `--all-targets` means package binaries/tests/examples/benches for the selected platform; it does not iterate all operating systems. `--all-features` is appropriate for Linux, but intentionally invalid on non-Linux hosts because it enables Linux-only roles.

`cargo check` verifies Rust compilation/type checking, **not native linking or runtime behavior**. Windows MSVC builds need the appropriate Visual C++ linker/SDK; Linux builds need a compatible native/cross linker and libc. Linking and runtime behavior are verified by building and running on the supported systems.

## Library and dependency boundaries

| Category | Choice | Boundary |
|---|---|---|
| Portable CLI | `clap` derive with std/help/usage/error-context/env; default features disabled | Parsing/help/version on all supported CLI targets; no server runtime dependencies |
| Linux role configuration | Optional `serde` derive and `toml` with only std/parse/serde | Compiled only with server or worker on Linux; strict bounded file input |
| Linux signal handling | Optional `ctrlc` with termination feature | SIGINT/SIGTERM/SIGHUP delivered to a bounded main-thread notification channel |
| Linux diagnostics/IDs | Optional `tracing` (std only), `tracing-subscriber` (std/fmt/json/registry, defaults off), `uuid` v4 | Structured events, explicit context propagation, bounded stderr queue; no network exporter or tracing environment filter |
| Storage, TLS, HTTP | `rusqlite` (bundled SQLite), `rustls` with `ring`, `ureq` with rustls | Used by the store, link, S3 and API crates; no async runtime |
| Development tooling | Pinned Cargo, rustfmt, Clippy | Toolchain components, not production services |
| OS/runtime prerequisites | Native linker/SDK for linking | Git and rootless Podman are Linux worker runtime tools, not server/CLI dependencies |
| UI | Nuxt server in `web/` ([web UI](web-ui.md)) | A separate `sentinel-web` process; not part of the Rust build |
| S3 / Tailcat | `sentinel-s3` client; Tailcat helper | Optional; no mandatory external service |

There is no `[workspace.dependencies]` catalog. Exact versions, including proc-macro and platform transitive dependencies, are committed in `Cargo.lock`. Only `crates/sentinel-bench` has a build script; maintained dependencies may use build scripts and proc macros. Inspect `cargo tree --locked --edges normal,build` with the selected target/features to distinguish the production tree from dev-only and inactive lockfile packages. Work lanes and bounded queue plumbing use the standard library.

## Foundation verification

Portable checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release
cargo metadata --locked --no-deps --format-version 1
cargo tree --locked
```

Run the feature-specific Linux commands in [configuration](configuration.md) in addition to portable checks; non-Linux builds cannot enable role features.

Cargo references: [Cargo workspaces](https://doc.rust-lang.org/cargo/reference/workspaces.html) and [feature resolver](https://doc.rust-lang.org/cargo/reference/resolver.html).
