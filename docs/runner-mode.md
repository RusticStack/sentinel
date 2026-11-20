# Runner mode

Sentinel's second mode: GitHub keeps orchestrating a workflow, and Sentinel supplies an ephemeral
self-hosted runner for each job whose `runs-on:` names one of its labels
([plan 16.10](../plan.md#1610-github-actions-runner-mode)). Demand, provisioning and reconciliation are
[the intake's](intake.md#demand-provisioning-and-reconciliation); this page is what the runner
sandbox promises once a lease is delivered, and what this release proves about it.

## One ephemeral runner per job

A worker that accepts a lease gets one just-in-time configuration, spends it on one container, and
destroys the container when the runner exits — which for a GitHub ephemeral runner is after its one
job. The configuration is single-use three times over: at GitHub (an ephemeral runner takes one job
and de-registers itself), in the store (the statement that reads it clears it, under a trigger that
makes it writable once), and on the worker, where it is handed straight to the runner and wiped
afterwards.

The sandbox a worker builds for a lease (`sentinel_worker::runner::Plan`) is a rootless container:

- the image its operator pinned by digest (`[runner] image`, [configuration](configuration.md#runner-image));
  a tag is refused, because the same tag is another image tomorrow;
- `--ephemeral` on the runner, one container per lease, named `sentinel-runner-<lease>`, so a worker
  that died leaves something a sweep can find and another start cannot quietly take;
- the class's CPU and memory from the lease, a pid limit, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, no core dumps and a read-only root filesystem;
- `/runner` and `/home/runner/_diag` as tmpfs, and the job's work directory as the one writable host
  path — a directory of that lease under the worker's data root, which the teardown removes.

A worker that states no image starts no runner: it declines every offer, so a runner lease never
lands on a machine that cannot start it.

## The configuration is a credential

The encoded configuration GitHub issues is the runner's own credential: whoever holds it can
register as that runner and take the job. It reaches the runner on **standard input**, and the
image's entry point ([`START`](../crates/sentinel-worker/src/runner.rs)) reads one line of it into a
0700 `noexec` tmpfs inside the container and execs the runner with `--jitconfig`. It is therefore
never on a command line (where every process of the account could read `/proc`), never in an
environment list, never in a host file, and never in the job's workspace.

| Sink | What keeps it out | Test |
|---|---|---|
| a log | nothing formats it; registration failures log the runner name, never the answer | `the_just_in_time_configuration_reaches_no_log_a_record_a_bundle_or_a_workspace` |
| a record | sealed at rest under a context that binds the tenant, repository and lease; cleared by the read that delivers it | the same test, plus `the_configuration_is_stored_sealed_and_read_exactly_once` |
| a bundle | runner mode sends no pipeline secret at all, so no delivery bundle exists for a lease | the same test |
| an environment listing | the container carries no environment of our making, and the worker lists lease ids, never bytes | the same test, and the sandbox's argument list |
| a workspace | the container's writable state is tmpfs or the lease's own scratch directory, and the configuration goes to neither | the same test, and `nothing_of_the_host_is_mounted_but_the_leases_own_scratch` |

The canary test issues a configuration containing a marker string through a recorded GitHub,
drives a real controller and a real worker session through placement, provisioning and delivery,
and then walks every sink: the process's whole log at TRACE, every file the deployment keeps
including the database, the bundle the worker never received, the list the controller can read
back, and the absence of a host workspace. The one place the marker is allowed is the frame the
worker received, which is the credential itself.

## Nothing writable survives

The configuration is wiped when the runner ends or the lease is stopped, the container is removed by
`--rm` even if the worker never gets to its teardown, and the lease's scratch directory is removed
with it. A worker killed mid-job leaves a named `sentinel-runner-<lease>` container, which its
bounded keepalive ends and `--rm` removes, and one directory under the worker's data root, which is
where a sweep looks; neither holds the configuration, which existed only in the runner's standard
input and the container's tmpfs.

## Egress without a route to the host

Runner mode needs the network by nature — the runner talks to GitHub — so it runs where the operator
granted it (`job_network = "egress"`). A container granted egress is not left with plain pasta: the
worker installs nftables refusals **into the container's own network namespace, before the runner
starts**, and fails the start if it cannot. Refused are the unspecified, loopback (off `lo` only, so
a job's own local sockets still work), link-local and cloud metadata addresses, Alibaba Cloud's
metadata address, the IETF protocol block, multicast and reserved ranges, **every address the host
itself holds**, and the controller's link endpoint by address and port. IPv6 leaves only through
loopback.

A worker without egress runs runners with `--network none`: a job that needs the network belongs on
a pool that grants it, not on a worker that does not.

## Fork pull requests

A job of a fork pull request runs code the tenant never merged, on a machine the tenant operates. So
it is served for a small set of jobs, under two conditions, and refused otherwise:

- **The tenant opts in.** `admin runner-mode fork-prs --tenant <slug> --enabled true` records the
  opt-in; it needs runner mode on, because a tenant with no runners has nothing to serve fork jobs
  from. Without it, a queued fork job is refused `failed:runner_fork_pr` with its audit row, and
  nothing is provisioned — the job stays queued at GitHub until its own timeout, which a tenant can
  avoid with GitHub's fork-approval settings.
- **A pool is the hostile-fork pool.** `admin pool fork --pool <name> --enabled true` marks the M09
  pool: a separate pool for fork jobs only. Placement's demand query enforces both directions — a
  fork job is demand only on a marked pool of an opted-in tenant, and a marked pool serves no trusted
  job — so a fork job whose tenant opted in without marking a pool waits, and a trusted job is never
  placed on the hostile pool.

The fork fact comes from the delivery: a `workflow_job` states the pull requests its commit belongs
to, and any whose head repository is not this repository makes the job a fork's. A pull request whose
head repository the parser cannot read counts as a fork, because what cannot be shown to be this
repository's own code is hostile. It is stored once, on the delivery and on the job, and never
rewritten.

## The shadow, and parity

A repository migrating by `runs-on:` first runs a non-required copy of each migrated job with a
Sentinel label beside the unchanged original, so both run on the same commits while GitHub's runners
stay authoritative: the copy is `name: sentinel / <original>` and no required check names it. What the
copy ran is the `runner_jobs` row its deliveries wrote, and the parity report compares it with the
original pair by pair — conclusion, test counts and duration — over a window of commits
([shadow parity](shadow-parity.md)). Switching the labels and dropping the copies is the
[migration switch](migration-switch.md), which keeps every job name — and so every check name a
required check names — exactly as it is.

## Actions secrets are GitHub's

Sentinel never receives Actions secrets. It does not ask: the App's runner-mode permissions are
Actions read and the self-hosted-runner grant ([GitHub App](github-app.md#runner-mode-permissions)),
nothing in the runner path calls a secrets endpoint, and a runner-mode job has no run spec and no
delivery bundle, so no secret of any kind travels over the worker link for it. The secrets a workflow
names exist only inside the runner process, for the life of the job, and die with the container.
Sentinel records lifecycle and timing only; job logs, annotations and artifacts stay on GitHub, so it
never stores what the runner masks.

## What this release verifies, and what it cannot

The tests named above, the fork-policy tests in
[`runner_provision`](../crates/sentinel-store/tests/runner_provision.rs),
[`runner`](../crates/sentinel-intake/tests/runner.rs) and
[`runner_admin`](../crates/sentinel/tests/runner_admin.rs), and the parser's fork cases cover the
decisions and the enforcement points: what a sandbox is built with, what the policy admits, which
demand a pool serves, and that no sink holds the configuration.

What they cannot cover, because it needs a real host: that rootless Podman accepts the plan and that
`podman unshare nsenter` can load the refusals into a runner container's namespace, that a real
`actions/runner` accepts the configuration on its standard input and takes exactly one job, and that
the refusals hold against a real metadata endpoint and the real link address. Those are the AR03
sandbox suite's gate on `reference-host` and `arm64-host` and its pilot workflow; this release states
the residual rather than claiming it. The image itself — the pinned `actions/runner` and its toolchains
— is AR05.
