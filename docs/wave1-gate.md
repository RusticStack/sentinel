# The Wave 1 verification gate

[`scripts/verify/wave1.sh`](../scripts/verify/wave1.sh) is the Wave 1 gate of [`TODO.md`](../TODO.md) as one repeatable run per verification host. Every stage is a command Wave 1 already names; the script adds the host rules around it and a record of what happened. It installs nothing and it never stops, restarts or reconfigures a service.

## Running it

On each host, as the unprivileged test account, from a disposable checkout of the commit under test:

```sh
git clone --depth 1 <repository> /var/tmp/sentinel-wave1 && cd /var/tmp/sentinel-wave1
scripts/verify/wave1.sh --host reference-host --out /var/tmp/wave1-record --detach
```

`--detach` puts the run in the background with its log in `<record-dir>.log` and its PID in `<record-dir>.pid`; stop it with `kill <pid>`, never by pattern. `--plan` prints every stage's command and what it needs without running anything, on any machine. `--list` prints the stage ids, and `--only a,b` runs a subset (the record is then `INCOMPLETE`).

Root prepares the host once beforehand, outside this script: [`bench/hosts/align-toolchain.sh`](../bench/hosts/align-toolchain.sh) (Rust, nextest, Node, pnpm 12.15, Podman), `cargo-deny`, and a Chromium-family browser for the browser stage (`SENTINEL_BROWSER` names it when it is not on `PATH`).

## Stages

| Host | Stage | What runs |
|---|---|---|
| `reference-host`, `kvm-host` | `static` | `cargo fmt-check`, `cargo lint`, `cargo lint-linux` |
| | `licenses` | `cargo licenses` |
| | `test-linux`, `test-cli` | the two full suites |
| `reference-host` | `podman` | the rootless-Podman worker suites with `SENTINEL_PODMAN_TESTS=1`: `podman`, `end_to_end`, `images`, `executor_faults`, `prefetch`, `slice`, `secret_isolation`, `recovery` |
| | `bootstrap` | the ignored `worker_bootstrap_script` tests |
| | `git-fixtures` | `scripts/git-fixtures/run.sh exercise` over the whole fixture matrix, then the `git_fixtures` binary |
| | `web` | `pnpm -C web install`, `typecheck`, `build`, `test:unit` |
| | `browser` | the browser suite, `--browser-runs` times in a row (default 5) |
| | `pending-suites` | email identity and `sentinel-mail`, first-run setup, account security, GitHub linking, the setup token |
| | `power-cut` | `power_cut_on_dm_flakey`, only with `--power-loss` and as root (dm-flakey on a loop device). Root and rootless Podman cannot share a run, so the root run is `--power-loss --only power-cut`, and the unprivileged run passes its `wave1.json` as `--power-record`: the stage then passes only when that record is from this host and commit, clean, with `power-cut` passed |
| | `bench` | `SMOKE_COMPILE=1 bench/smoke.sh` |
| | `doc-links` | `scripts/check-doc-links.sh` |
| `arm64-host` | `test-worker` | `cargo test-worker` |
| | `podman` | the same rootless-Podman worker suites |
| `kvm-host` | `microvm` | the job suites under Firecracker with `SENTINEL_MICROVM_TESTS=1` |

## Host rules it enforces

- It refuses to run anywhere but Linux on the host's architecture, refuses WSL, and refuses a checkout or a record directory outside `/var/tmp` (or `/tmp`), so `/srv/sentinel` is never touched.
- Every stage runs under `nice -n 19 ionice -c3` with `CARGO_BUILD_JOBS` at most 6, and under `flock -x -o` on the shared lock (`SENTINEL_VERIFY_LOCK`, default `/var/tmp/sentinel-verify.lock`), so it waits for a benchmark instead of disturbing it and nothing it starts keeps the lock.
- `/proc/pressure/cpu` is read before every stage. Above `--max-cpu-pressure` (default 25) the stage is recorded `pending` and does not run.
- A stage whose prerequisite is missing is `skipped` with the reason. A Podman, microVM or power-cut stage whose log holds a test's `skipped:` line fails, because that test returned without testing anything.

## The record

`<record-dir>/wave1.json` holds the verdict, the host label, the commit and whether the tree was dirty, the kernel, the toolchain versions, CPU pressure at the start, and one entry per stage with its status, duration and the SHA-256 of its log under `logs/`. `verdict.txt` is the one-line result. The record names the host only by the label given to `--host`; stage logs are raw test output and are reviewed before any of it is published.

| Verdict | Exit | Meaning |
|---|---|---|
| `PASS` | 0 | every stage of this host ran and passed |
| `FAIL` | 1 | at least one stage failed |
| `INCOMPLETE` | 3 | nothing failed, but a stage was skipped, pending or not selected |

A usage error or a refused path exits 2 before anything runs.

## What it does not do

The record's `not_automated` list repeats these, so a `PASS` never implies them:

- V02: building the container and web images, `podman compose --profile web up`, `podman healthcheck run`, `SIGTERM`, the Quadlet dry run and the web image's licence-inventory decision.
- `web/bench/web-bench.mjs` against a live `sentinel-web`, and refreshing the generic Git timings on the fixtures.
- The checks behind owner prerequisites (RW05's `members:read`, Forgejo over SSH and GitLab over HTTPS).
- Fixing a failure at its cause and ticking a `Closes` entry: those stay with whoever reads the record.
