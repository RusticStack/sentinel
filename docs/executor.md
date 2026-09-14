# Worker execution: workspaces, checkout and rootless containers (W03)

Implemented in `crates/sentinel-worker` (Linux only; empty elsewhere), with the report and spec messages added to the [worker link](worker-link.md) and the `dispatch::report`/`spec_bytes` store operations. `sentinel worker` uses it whenever rootless Podman answers; otherwise it declines every offer and says why.

## Nothing is reused

Every attempt gets `<data_dir>/workspaces/<attempt>`, created empty exactly once (`Workspace::create` refuses an existing directory — a leftover belongs to W07's reconciliation, not to a new attempt) and destroyed after finalization. A rerun is a new attempt with a new directory. `Workspace::leftovers` lists what an earlier process left behind.

## The commit, not the branch

`checkout::checkout` asks Git for the pinned SHA itself: `git init`, `git fetch --no-tags --depth 1 -- <repo> <sha>`, `git checkout --detach FETCH_HEAD`, then `git rev-parse HEAD` must equal the SHA or the checkout is a `Preparation` failure. The branch name on the run is provenance only. Every Git invocation runs with a cleared environment, `GIT_TERMINAL_PROMPT=0`, `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL=/dev/null`, in its own process group under one shared deadline (`CHECKOUT_TIMEOUT`, 10 min); past it the whole group is killed. A repository argument that looks like an option is refused before Git sees it.

Credentials, when the controller issues them (GitHub App installation tokens are G-tasks), reach Git through `GIT_ASKPASS`: an owner-only helper script that answers from its own environment and is deleted the moment the fetch returns. The token is never in a URL, never in `.git/config`, never in the job's environment, never in a log line. The mechanism is tested with a local repository; the call site changes when the controller starts issuing tokens.

Submodules and LFS are not fetched. Extra checkouts and mirrors are later tasks.

## The container

`podman::probe` refuses to start without **rootless** Podman on **cgroup v2**: an executor that cannot isolate is not one. Every container is created with the baseline the F07 probe proved enforceable ([feasibility probes](feasibility-probes.md#2-rootless-podman-resource-enforcement)):

| Flag | Why |
|---|---|
| `--cpus <job>` | CPU quota from the compiled resources (`cpu_millis`) |
| `--memory <job> --memory-swap <job>` | memory limit with no swap escape; the kernel OOM-kills inside the cgroup |
| `--pids-limit 4096` | a fork bomb ends inside its cgroup |
| `--network none` | loopback only; no egress from job steps |
| `--read-only --tmpfs /tmp` | the image is immutable; `/tmp` (1 GiB tmpfs) and the workspace are the writable places |
| `--cap-drop ALL --security-opt no-new-privileges` | `CapEff` all zero, and nothing can regain it |
| rootless user namespace | uid 0 inside is the worker account outside; files the job creates in the workspace are the worker's |
| `--volume <workspace>:/workspace --workdir /workspace` | the only bind mount |
| `--pull never`, image `name@sha256:…` | the bytes the run pinned; the pull is a separate, bounded preparation step (`IMAGE_PULL_TIMEOUT`, 15 min), refused for an unpinned reference |
| `--name sentinel-<attempt>`, labels `io.sentinel.worker`/`io.sentinel.attempt` | ownership recorded in the runtime itself: `podman::owned(worker)` lists what this worker created, whatever its state, for W07 |

The container's main process is a keepalive (`/bin/sh` loop that exits on `TERM`); steps run in it with `podman exec` — the image must provide `/bin/sh`, which the run spec's shells already require. There is no Docker socket, no privileged flag, and no pipeline key that loosens any of this.

`Container::exec` runs one `StepCommand`: its argv, its environment with the worker's context appended **after** the pipeline's (`SENTINEL_RUN`, `SENTINEL_JOB`, `SENTINEL_ATTEMPT`, `SENTINEL_SHA`, `SENTINEL_WORKSPACE`, `CI`), so a pipeline cannot spoof them; its working directory under `/workspace`; its timeout. Exit status and signal (Podman's `128 + n`) are reported as such; a step past its timeout stops the whole container — steps are sequential and the attempt is over. Output tails of 64 KiB per stream are kept for diagnostics; streaming logs are W05.

`Container::destroy` is `podman stop -t 2` then `podman rm -f`. Finalization runs both teardowns even when one fails.

## The attempt

`attempt::run` is the lifecycle the controller's state machine expects, reported under the attempt's fence: `PreparationStarted` → workspace, checkout, image pull, container start → `StepsStarted` → each step in order → `FinalizationStarted` → teardown → `Passed` or `Failed(class)`:

| What happened | Class |
|---|---|
| fetch, pull or container start failed | `Preparation` |
| a step exited non-zero | `CommandFailed` |
| a step died from a signal | `CommandSignaled` |
| a step passed its timeout | `ExecutionTimeout` |
| cancel seen between steps | `Canceled` |

`executor::Executor` is the link's `Executor`: it takes an offer when the runtime is usable and fewer than 64 attempts are held, asks for the run spec over the link (`NeedSpec` → `Spec` chunks of 48 KiB, at most 1 MiB), decodes it and starts the attempt on its own thread. Reports go out on the live session in order; without a session they queue in memory and are replayed at the next attach (a durable spool is W05). A `stop` from the controller flips the attempt's cancel flag and removes its container; it is not reported, because the controller already counts the attempt as gone.

On the controller, `dispatch::report` checks that the attempt is held by that worker under that fence and then applies the event through the state machine; a stale or foreign report changes nothing and is counted. A terminal report releases the reservation, decides dependents and wakes the dispatcher.

## What is not here yet

Step conditions (`if:`), phase timings and the exact failure taxonomy (OOM detection, signal versus timeout races) are W04. Log capture and streaming are W05; only bounded tails exist. Cancellation as desired state, lease expiry and graceful/forced termination budgets are W06; a cancel today is a `stop` order or a flag checked between steps. Crash reconciliation of owned containers and leftover workspaces is W07 — the ownership record (`podman::owned`, `Workspace::leftovers`) exists, the reaper does not. Caches, artifacts and secrets are their own parts. Disk quotas on the workspace are not enforced (no `io` delegation in the rootless setup; see F07).

## Verification

`crates/sentinel-worker/tests/checkout.rs` (any Linux, needs `git`): the pinned commit is checked out even when it is not the branch head and only it is fetched; a workspace is never reused and destroying it removes the checkout; an unknown revision is a `Preparation` failure that leaves no checkout; a transport Git refuses and an option-shaped repository are refused in bounded time; a credential delivered through askpass leaves neither the helper nor the secret behind.

`crates/sentinel-worker/tests/podman.rs` and `tests/end_to_end.rs` run only with `SENTINEL_PODMAN_TESTS=1` as an account with rootless Podman (they report "skipped" otherwise, never a pass). Executed on 2026-09-14 in WSL2 as `sentinelbench` (Podman 4.9.3, runc, cgroup v2 via systemd) against `busybox@sha256:73aaf…`:

- inside the container `cpu.max` is `50000 100000` for half a core, `memory.max` the requested bytes, `pids.max` the limit, `CapEff` all zero, `lo` the only interface, the root filesystem read-only, `/tmp` and `/workspace` writable and a file written in `/workspace` visible on the host; exit 3 is exit 3, `kill -9 $$` is signal 9, the pipeline's `SENTINEL_ATTEMPT` cannot override the worker's, a step past its timeout stops the container and nothing runs after it; `podman::owned` lists the container while it exists and nothing after `destroy`.
- end to end: a controller with a store, a worker with the real executor over loopback TLS, a local repository and a two-job run — the job that reads the checked-out file and `SENTINEL_SHA` and writes into the workspace reaches `Passed`; the job that exits 3 reaches `Failed` with `CommandFailed`; every phase timestamp is stamped in order by the worker's reports (eight reports counted); capacity is released; no container and no workspace is left behind; the worker stops without waiting for a beat and the controller drains.

See [worker link](worker-link.md) for the session, [core contracts](core-contracts.md) for the state machine, and [development](development.md#linux-executor-work-f05f07-and-w03-onward) for preparing an account.
