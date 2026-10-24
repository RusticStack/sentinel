<div align="center">

# Sentinel

**Fast, self-hosted CI that treats every second as a budget.**

Native pipelines, durable distributed execution and local-first caching,<br>
built in Rust for teams that want control of their hardware and their data.

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-2563eb?style=flat-square" alt="MIT license"></a>
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/rust-1.97.0-b7410e?style=flat-square&logo=rust&logoColor=white" alt="Rust 1.97.0"></a>
  <a href="TODO.md"><img src="https://img.shields.io/badge/status-pre--release-d97706?style=flat-square" alt="Pre-release status"></a>
  <a href="docs/rust-foundation.md#platform-and-feature-matrix"><img src="https://img.shields.io/badge/server_%26_worker-Linux-334155?style=flat-square&logo=linux&logoColor=white" alt="Linux server and worker"></a>
</p>

</div>

> [!WARNING]
> Sentinel is under active development and does not have a stable release yet. The first release will provide native `.sentinel.yml` pipelines on Linux workers. Configuration, APIs and on-disk formats may change before then.

## Why Sentinel?

Sentinel is a purpose-built CI engine, not a dashboard around another runner. It combines the controller, worker protocol, pipeline compiler, cache and log storage in one auditable system, with performance measured against real CI workloads on the same hardware.

The goal is **sub-minute warm pull-request checks on hardware where the equivalent CI previously took five minutes or more**. That is a target, not a published result. Current measurements and their exact conditions live in the [benchmark records](bench/) and [benchmark contracts](docs/benchmark-contracts.md).

## What you get

- **Native pipelines.** A strict, versioned `.sentinel.yml` schema with job dependencies, conditions, resources, caches, artifacts, secrets and concurrency controls.
- **Fast, isolated execution.** Fresh rootless Podman workspaces on Linux, no job network by default and exact-revision checkouts. Firecracker microVM execution is in development for KVM hosts.
- **Local-first caching.** Separate download, dependency and compiler caches, content-addressed Git mirrors and reusable runtime images, with explainable hit and miss reasons.
- **Durable by design.** SQLite metadata, fenced worker leases, restart recovery, resumable log spooling and explicit partial-data states instead of silent loss.
- **A real multi-tenant control plane.** Organizations and personal namespaces, scoped credentials, local and GitHub sign-in, MFA, OAuth, CLI/MCP access and tenant-owned workers.
- **Useful feedback everywhere.** A web interface, human- and machine-readable CLI output, structured diagnostics, live logs and native GitHub Checks.
- **Your repositories, your infrastructure.** Generic Git works with Gitea, Forgejo, GitLab and bare repositories; GitHub App integration adds native pull-request checks.

## How it works

```text
 Git push, pull request or manual run
                  |
                  v
        +-------------------+
        | Sentinel controller|
        | API, auth, queue,  |
        | SQLite and storage |
        +---------+---------+
                  | authenticated worker link
          +-------+-------+
          |               |
          v               v
   +-------------+ +-------------+
   | Linux worker| | Linux worker|
   | containers  | | containers  |
   | or microVMs | | or microVMs |
   +-------------+ +-------------+
```

The controller never executes jobs. Workers run as separate processes, receive only work they are authorized and equipped to run, and report logs and outcomes through durable, fenced attempts.

## A pipeline looks like this

```yaml
schema: 1
on: [push]

jobs:
  test:
    image: docker.io/library/rust:1-alpine
    resources: { cpu: 2, memory: 1GiB }
    timeout: 10m
    steps:
      - id: build
        run: cargo build --locked
      - id: test
        run: cargo test --locked
```

Explore [valid pipeline fixtures](fixtures/pipelines/valid/), ready-to-adapt [cache recipes](fixtures/recipes/) and the complete [pipeline schema](docs/pipeline-schema.md).

## Quick start

### Validate a pipeline

Sentinel's CLI builds on Linux and Windows. The pinned toolchain is selected automatically by `rustup`.

```sh
git clone https://github.com/RusticStack/sentinel.git
cd sentinel
cargo run -p sentinel -- pipeline validate fixtures/pipelines/valid/minimal.yml
```

### Start a development deployment

The controller and worker require Linux. From the repository root, use separate terminals:

```sh
cargo dev-server --data-dir "$PWD/data/controller"
```

```sh
cargo dev-worker --data-dir "$PWD/data/worker"
```

Then follow [operator first run](docs/development.md#operator-first-run) to create the first administrator and [configuration](docs/configuration.md) to enroll and connect a worker. The example commands start the processes; they do not bypass authentication or worker enrollment.

## Project status

| Area | State |
|---|---|
| Native pipeline compiler and validation | Implemented; pre-release |
| Linux controller and rootless-Podman workers | Implemented; pre-release |
| Multi-tenancy, authentication, OAuth and secrets | Implemented; pre-release |
| Logs, artifacts, caches, recovery and retention | Implemented; pre-release |
| Web interface, CLI, MCP and GitHub Checks | Implemented; pre-release |
| Same-hardware optimization and pilot measurements | In progress |
| Firecracker microVMs for Linux jobs | In development |
| GitHub Actions runner mode and Windows jobs | Planned after v0.1 |

The v0.1 release still requires the remaining benchmark and pilot work, a full re-audit and the release gates. [TODO.md](TODO.md) is the authoritative task tracker; [plan.md](plan.md) explains the architecture and longer-term direction.

## Documentation

Start with the task you want to accomplish:

- **Run Sentinel:** [development setup](docs/development.md), [configuration](docs/configuration.md) and [CLI reference](docs/cli.md).
- **Write pipelines:** [schema](docs/pipeline-schema.md), [cache recipes](docs/recipes.md) and [examples](examples/).
- **Understand the system:** [architecture and product plan](plan.md), [runtime foundations](docs/runtime-foundation.md), [storage](docs/storage.md), [executor](docs/executor.md) and [worker link](docs/worker-link.md).
- **Integrate:** [HTTP API](docs/api.md), [MCP](docs/mcp.md), [sources and intake](docs/intake.md) and [compatibility policy](docs/compatibility.md).
- **Evaluate performance:** [benchmarking](docs/benchmarking.md), [benchmark contracts](docs/benchmark-contracts.md) and [performance research](docs/performance-research.md).

## Contributing

Bug reports and focused pull requests are welcome. Please read [the development guide](docs/development.md) and [AGENTS.md](AGENTS.md) before making changes, and discuss substantial features or architectural changes first.

Keep pull requests focused, include behavior and failure-path tests where appropriate, and never commit credentials or production data. Commit messages and code must stay free of AI attribution; disclose AI-assisted work in the pull-request description instead.

## License

Sentinel is free and open-source software under the [MIT License](LICENSE).
