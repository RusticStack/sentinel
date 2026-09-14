# Worker execution: workspaces, checkout, rootless containers and steps (W03–W04)

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

`Container::exec` runs one `StepCommand`: its argv, its environment with the worker's context appended **after** the pipeline's (`SENTINEL_RUN`, `SENTINEL_JOB`, `SENTINEL_ATTEMPT`, `SENTINEL_SHA`, `SENTINEL_WORKSPACE`, `CI`), so a pipeline cannot spoof them; its working directory under `/workspace`; its timeout. Exit status and signal (Podman's `128 + n`) are reported as such; a step past its timeout stops the whole container — steps are sequential and the attempt is over. Output tails of 64 KiB per stream are kept for diagnostics; the same bytes stream through the [log pipeline](logs.md) as they are produced.

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

## Steps (W04)

Steps run in order in the attempt's container, each as the run spec compiled it: `/bin/sh -e -c` (fail at the first failing command, with its status) or `bash -eo pipefail -c` (the image must provide Bash); the job's environment, then the step's overriding by name, then the worker's context (`SENTINEL_RUN|JOB|ATTEMPT|SHA|WORKSPACE`, `CI`) last so a pipeline cannot spoof it; the working directory joined under `/workspace`; the step's timeout, or the job's, **bounded by what is left of the job's budget** so a job cannot outlive its timeout through many steps each within theirs. A step after a failed one never starts and is recorded as `NotRun`.

A step's `if:` is evaluated on the worker (`Phase::Worker`, the C06 evaluator) against the job context the controller sends with the spec — `job.id|name`, `repo.id|name`, `run.id`, `event.sha` (the pinned commit), `event.ref` (the run's ref name), `needs.<job>.result` and `success()`/`failure()`/`always()`/`cancelled()` from the dependency outcomes and cancel state — and `hash_files` over the private checkout. `false` skips the step (`Skipped`); a non-boolean, a type error or a value the run does not hold is a `Preparation` failure naming the step and the reason, never a default. Event fields intake does not record yet (`event.name|key|base_ref|pr_number`) are exactly that case until the G-tasks land.

The verdict keeps every distinction the plan asks for, and the summary records it per step:

| What happened | Failure class | Step outcome |
|---|---|---|
| exit 0 | — | `Passed` |
| `if` false | — | `Skipped` |
| non-zero exit | `CommandFailed` | `Failed { code }` |
| killed by a signal, OOM counter unchanged | `CommandSignaled` | `Signaled { signal }` |
| killed and the cgroup's `oom_kill` counter moved | `OutOfMemory` | `OutOfMemory` |
| past its (bounded) timeout; the container is stopped | `ExecutionTimeout` | `TimedOut` |
| Podman could not run it (exit 125–127 with its `Error:` line; a shell's own 126/127 stays a command failure) | `Runtime` (new class, `infra_failed`) | `Runtime` |
| fetch, pull, container start, `if` unresolved | `Preparation` | — |
| cancel seen between steps | `Canceled` | — |

OOM is read from the host's view of the container's cgroup (`/sys/fs/cgroup<CgroupPath>/memory.events`, path from `podman inspect`), before and after a failed step: after an OOM the pages that caused it stay charged, so a process exec'd inside to read the counter could be the next victim — the first version of this did exactly that and misreported an OOM as a signal.

**Timings.** Every phase is measured with a monotonic clock in nanoseconds: checkout, image pull, container start, all steps, finalization, and each step. Absent means not measured. They travel in the `AttemptSummary` (`sentinel-protocol::summary`, format byte 1, at most 32 KiB) with the terminal `Report` and are stored once on the attempt row (migration 15; the trigger refuses a replacement). `dispatch::attempt_summary` reads it back; W08 exposes it.

## What is not here yet

Log tail/follow over the API is W08 (`admin logs` reads the files host-locally); only bounded tails exist. Cancellation as desired state, lease expiry and graceful/forced termination budgets are W06; a cancel today is a `stop` order or a flag checked between steps. Crash reconciliation of owned containers and leftover workspaces is W07 — the ownership record (`podman::owned`, `Workspace::leftovers`) exists, the reaper does not. Caches, artifacts and secrets are their own parts. Disk quotas on the workspace are not enforced (no `io` delegation in the rootless setup; see F07).

## Verification

`crates/sentinel-worker/tests/checkout.rs` (any Linux, needs `git`): the pinned commit is checked out even when it is not the branch head and only it is fetched; a workspace is never reused and destroying it removes the checkout; an unknown revision is a `Preparation` failure that leaves no checkout; a transport Git refuses and an option-shaped repository are refused in bounded time; a credential delivered through askpass leaves neither the helper nor the secret behind.

`crates/sentinel-worker/tests/podman.rs` additionally checks `sh -e` stops at the first failing command with its status, that a command missing inside the shell is exit 127 without Podman's `Error:` line while a missing working directory is the runtime's error, and that the OOM counter reads zero on a fresh container. `tests/end_to_end.rs` (W04) runs six jobs: `inspect` passes with every phase timed; `broken` fails at `false` with `Failed { code: 1 }` and its second step `NotRun`; `gated` skips a false `if` and passes a step whose `if` uses `needs.inspect.result`, `hash_files` on the checkout, `event.sha` and `success()`; `unknown` (`event.name`) is a `Preparation` failure naming the step; `oom` (128 MiB, 300 MiB into tmpfs) is `OutOfMemory`; `slow` (job timeout 2 s, `sleep 30`) is `ExecutionTimeout` with the next step `NotRun`; 24 reports applied, none stale; every summary is stored and decodes.

`crates/sentinel-worker/tests/podman.rs` and `tests/end_to_end.rs` run only with `SENTINEL_PODMAN_TESTS=1` as an account with rootless Podman (they report "skipped" otherwise, never a pass). Executed on 2026-09-14 in WSL2 as `sentinelbench` (Podman 4.9.3, runc, cgroup v2 via systemd) against `busybox@sha256:73aaf…`:

- inside the container `cpu.max` is `50000 100000` for half a core, `memory.max` the requested bytes, `pids.max` the limit, `CapEff` all zero, `lo` the only interface, the root filesystem read-only, `/tmp` and `/workspace` writable and a file written in `/workspace` visible on the host; exit 3 is exit 3, `kill -9 $$` is signal 9, the pipeline's `SENTINEL_ATTEMPT` cannot override the worker's, a step past its timeout stops the container and nothing runs after it; `podman::owned` lists the container while it exists and nothing after `destroy`.
- end to end: a controller with a store, a worker with the real executor over loopback TLS, a local repository and a two-job run — the job that reads the checked-out file and `SENTINEL_SHA` and writes into the workspace reaches `Passed`; the job that exits 3 reaches `Failed` with `CommandFailed`; every phase timestamp is stamped in order by the worker's reports (eight reports counted); capacity is released; no container and no workspace is left behind; the worker stops without waiting for a beat and the controller drains.

See [worker link](worker-link.md) for the session, [core contracts](core-contracts.md) for the state machine, and [development](development.md#linux-executor-work-f05f07-and-w03-onward) for preparing an account.
