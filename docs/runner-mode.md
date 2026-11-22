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
- one container per lease, named `sentinel-runner-<lease>`, so a worker that died leaves something a
  sweep can find and another start cannot quietly take. The runner takes one job and exits because
  the configuration GitHub issues is an ephemeral runner's, which is where its ephemerality comes
  from (`run --jitconfig` takes no `--ephemeral`);
- the class's CPU and memory from the lease, a pid limit, `--cap-drop ALL`,
  `--security-opt no-new-privileges` and no core dumps;
- `/home/runner/_diag` and `/tmp` as bounded tmpfs mounts (`--tmpfs` refuses `uid=`/`gid=`, so they
  keep the runtime's 1777 inside a container whose only user is the runner), and `--userns keep-id`,
  which makes the image's runner the worker's own account — and so the job's work directory, the one
  writable host path, a directory of that lease under the worker's data root that the teardown
  removes, writable by the runner and owned by the account that cleans it up. Everything else the
  runner writes lives in the container's own layer, which goes with the container.

A worker that states no image starts no runner: it declines every offer, so a runner lease never
lands on a machine that cannot start it.

## The configuration is a credential

The encoded configuration GitHub issues is the runner's own credential: whoever holds it can
register as that runner and take the job. It reaches the runner on **standard input**: the image's
entry point ([`START`](../crates/sentinel-worker/src/runner.rs),
[`examples/runner/sentinel-runner`](../examples/runner/sentinel-runner)) reads one line of it,
bounds it, and execs `/home/runner/bin/Runner.Listener run --jitconfig <value>`. The runner accepts a
just-in-time configuration as an argument and nowhere else, so inside the sandbox the value is that
one process's argv — reachable by the container's own processes, and by the worker account that
already holds the credential — and the listener writes the settings it derives from it (`.runner`,
`.credentials`, `.credentials_rsaparams`) into its installation directory. Both are the container's:
the value lives in the argv of a process in it, the files in its own writable layer, and both go when
the container does. No host path the worker manages holds either, and neither does anything Sentinel
keeps.

| Sink | What keeps it out | Test |
|---|---|---|
| a log | nothing formats it; registration failures log the runner name, never the answer | `the_just_in_time_configuration_reaches_no_log_a_record_a_bundle_or_a_workspace` |
| a record | sealed at rest under a context that binds the tenant, repository and lease; cleared by the read that delivers it | the same test, plus `the_configuration_is_stored_sealed_and_read_exactly_once` |
| a bundle | runner mode sends no pipeline secret at all, so no delivery bundle exists for a lease | the same test |
| an environment listing | the container carries no environment of our making, and the worker lists lease ids, never bytes | the same test, and the sandbox's argument list |
| a workspace | the job's work directory is a volume the worker owns, and the configuration never enters it; the settings the listener derives stay in the container's own layer, which the teardown removes | the same test, and `a_runner_sandbox_runs_once_and_leaves_nothing_behind` |

The canary test issues a configuration containing a marker string through a recorded GitHub,
drives a real controller and a real worker session through placement, provisioning and delivery,
and then walks every sink: the process's whole log at TRACE, every file the deployment keeps
including the database, the bundle the worker never received, the list the controller can read
back, and the absence of a host workspace. The one place the marker is allowed is the frame the
worker received, which is the credential itself.

## Nothing writable survives

The configuration is gone when the runner ends or the lease is stopped: its only copy outside the
worker's own credential store is in a process that dies with the container, whose layer `--rm`
removes even if the worker never gets to its teardown, and the lease's scratch directory is removed
with it. A worker killed mid-job leaves a named `sentinel-runner-<lease>` container, which its
bounded keepalive ends and `--rm` removes, and one directory under the worker's data root, which is
where a sweep looks; neither holds the configuration, which existed only in the runner's standard
input and, inside the container, in that runner's argv and the settings files it wrote there.

## Egress without a route to the host

Runner mode needs the network by nature — the runner talks to GitHub — so it runs where the operator
granted it (`job_network = "egress"`). A container granted egress is not left with plain pasta: the
worker installs nftables refusals **into the container's own network namespace, before the runner
starts**, and fails the start if it cannot. Refused are the unspecified, loopback (off `lo` only, so
a job's own local sockets still work), link-local and cloud metadata addresses, Alibaba Cloud's
metadata address, the IETF protocol block, multicast and reserved ranges, **every address the host
itself holds**, and the controller's link endpoint by address and port. IPv6 leaves only through
loopback.

A worker without egress therefore serves no runner at all: a runner registers with GitHub and fetches
its job from it before anything else can happen, so a sandbox with `--network none` would spend its
registration without ever coming online. `[runner]` beside `job_network = "none"` is refused when the
configuration loads, with that reason ([configuration](configuration.md#runner-image)), rather than
after a lease has been burnt on a runner that could not start.

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

## Cache and artifacts on the worker's own disk

A runner-mode job's `actions/cache`, the `setup-*` actions' caches and `upload-artifact`/`download-artifact`
are served from the worker host's NVMe, not from GitHub's storage: inside each sandbox the two service
hosts resolve to a Sentinel endpoint on the worker, a certificate authority minted with that sandbox
lets the endpoint terminate their TLS, and everything else GitHub's runner talks to is untouched
([cache and artifacts](actions-cache.md)).

- The sandbox is built with two `/etc/hosts` entries, one read-only mount of **its own** anchor at
  `/sentinel-ca/ca.crt`, and `NODE_EXTRA_CA_CERTS` naming that path — a path, never a secret, so the
  container still carries no secret of Sentinel's in its environment.
- A worker serves runner mode only when its `[runner]` states `actions_address`, the address its
  sandboxes reach that endpoint on. A worker that states the image and no address declines every
  runner lease: its runners' caches and artifacts would go to GitHub's storage
  ([configuration](configuration.md#runner-image)).
- The boundary — tenant, repository, trust, platform — is the lease's, stated by the controller once a
  delivery binds the job; a sandbox that has not been told refuses every cache and artifact call, and
  a fork job's writes land in a scope no trusted job reads.

This release serves the endpoint, the authority, the name answers and the boundary; that a real
`actions/runner` in a rootless sandbox reaches it, and the pilots' measured restore and upload times,
are AR03's host suite and the benchmark wave ([cache and artifacts](actions-cache.md#what-this-release-verifies-and-what-it-cannot)).

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
Sentinel records lifecycle and timing only; job logs and annotations stay on GitHub. Artifacts do not:
`upload-artifact` is served from the worker's own disk ([cache and artifacts](actions-cache.md)), a
zip of files the job chose to upload rather than anything the runner masks, and the version of it
GitHub would have stored is never written there.

## The runner image and its update policy

A worker starts runners from an image it pins by digest, built from
[`examples/Containerfile.runner`](../examples/Containerfile.runner):

- **What it carries.** The official `actions/runner` at a pinned version, its own entry point at
  `/usr/local/bin/sentinel-runner` ([`START`](../crates/sentinel-worker/src/runner.rs)), and the
  tools a runner needs to start and check a job out — `bash`, `ca-certificates`, `curl`, `git`,
  `gzip`, `jq`, the `libicu` its runtime loads, `tar` and `unzip`. This image carries only what the
  runner itself needs; the toolchains a workflow expects are in the images built on it
  ([runner images](runner-images.md)).
- **Pinned version.** `2.338.2`, recorded in the image's `io.sentinel.runner.version` label, so an
  operator reads what a digest carries without running it. The build downloads the release's own
  tarball and checks it against the sha256 in that release's notes, so the image cannot carry a build
  the version does not name. It fails on any architecture without an official artifact: `amd64`
  takes `actions-runner-linux-x64`, `arm64` takes `actions-runner-linux-arm64`.
- **Not root.** The runner runs as uid 1001 (`runner`, `HOME=/home/runner`, installed under
  `/home/runner`), which the sandbox maps to the worker's own account with `--userns keep-id`, so a
  job's work directory is writable by it.

**The update policy is the image's, not the runner's.** `run` is a just-in-time configuration's only
interface, and it takes no `--disableupdate`: the updater is not switched off by a flag. What holds
instead is the structure around it — a sandbox starts from the digest the worker pinned, the worker
pulls never, and a runner that replaced itself would do so in that container's own layer, which the
teardown removes; the next runner is the same digest again. So a job never runs a runner build the
operator did not pin, and the version that moves is the image's:

- **pinned**: the operator states the reference by digest and a tag is refused
  ([runner image](configuration.md#runner-image));
- **rebuilt inside GitHub's 30-day window**: a self-hosted runner more than 30 days behind the
  current release is refused registration and stops being handed jobs
  ([the changelog](https://github.blog/changelog/2026-06-12-github-actions-minimum-version-enforcement-timeline-for-self-hosted-runners/));
- **the version is bumped by a commit that also moves the checksum**, so moving it is a reviewed
  change. That window is a review obligation: nothing in the image, the worker or the store checks
  it, and a digest that falls behind fails at GitHub rather than here.

**Publishing it.** [`scripts/release/publish-runner-image.sh`](../scripts/release/publish-runner-image.sh)
builds the image, checks that the version its label reports is the one the Containerfile pins, pushes it,
and prints the line a worker states:

```sh
scripts/release/publish-runner-image.sh ghcr.io/rusticstack/sentinel-runner
# a worker pins this line:
# image = "ghcr.io/rusticstack/sentinel-runner@sha256:…"
```

Run it once per architecture that serves runner mode, since `amd64` and `arm64` build different artifacts
and publish different digests, and publish before any worker names one: a sandbox pulls never, so a worker
that states a digest it does not hold declines every runner lease. Once an image is published, the sandbox
suite stops being a skip and becomes a gate — pull the digest, then run it with `SENTINEL_PODMAN_TESTS=1`
and `SENTINEL_RUNNER_IMAGE` set to the same reference
([below](#what-this-release-verifies-and-what-it-cannot)).

## What this release verifies, and what it cannot

The cache and artifact endpoint's own tests, named in
[cache and artifacts](actions-cache.md#what-this-release-verifies-and-what-it-cannot), cover the
sandbox's wiring and the boundary; the tests named here cover provisioning and the credential. The
fork-policy tests in
[`runner_provision`](../crates/sentinel-store/tests/runner_provision.rs),
[`runner`](../crates/sentinel-intake/tests/runner.rs) and
[`runner_admin`](../crates/sentinel/tests/runner_admin.rs), and the parser's fork cases cover the
decisions and the enforcement points: what a sandbox is built with, what the policy admits, which
demand a pool serves, and that no sink holds the configuration.

[`runner_sandbox`](../crates/sentinel-worker/tests/runner_sandbox.rs) drives a real runner image
through [`Plan`](../crates/sentinel-worker/src/runner.rs) — stage, start, destroy — against the digest
`SENTINEL_RUNNER_IMAGE` names, with a fake configuration that carries a marker: the container exists
while the runner runs and is gone after, the run ends by itself with a code, the lease directory is
gone after the teardown, and the marker is in neither the container's environment nor its command
line nor any file under the lease directory. The configuration it hands over is one the listener
cannot use, so the runner ends instead of retrying a server that does not exist — the one thing a
fake configuration cannot provoke is the exit a real one's single job produces. It also proves the
refusal: an empty configuration and one past the worker's frame bound are rejected before anything is
created. That suite is gated on `SENTINEL_PODMAN_TESTS`, so it skips where no runtime is available
and is a gate where one is.

What was proved on a container runtime for this release, by hand, on one x86_64 host (2026-11-20):

- **The image builds**, under rootless Podman 4.9.3 inside the build container: `podman
  --cgroup-manager=cgroupfs build --network=host --isolation=chroot -f examples/Containerfile.runner`,
  32.5 s wall, with the release tarball's sha256 checked inside the build; and under rootful Docker
  29.9.3, 66.5 s clean and 0.47 s cached.
- **The plan's namespace mapping works.** A container created with the plan's flags
  (`--userns keep-id:uid=1001,gid=1001`, `--tmpfs /home/runner/_diag:…,size=…`, `--tmpfs
  /tmp:…,size=…`, the lease's work directory as a volume) reports `uid=1001(runner)` inside, and the
  runner wrote to `/tmp`, to `/home/runner/_diag`, to the host work directory and to its own
  installation directory — the last because, as measured, the listener writes the settings it derives
  from the configuration there. Files it leaves in the work directory are owned by the worker's own
  account, which is what lets the teardown remove them without a second identity.
- **`--tmpfs` refuses `uid=` and `gid=`** (`unknown mount option "uid=1001"`), which is why the mounts
  keep the runtime's 1777 rather than an explicit ownership.
- **The entry point carries a real listener.** `podman exec -i <sandbox> /usr/local/bin/sentinel-runner`
  with one line of a fake configuration on standard input started `bin/Runner.Listener` with
  `--jitconfig`, which materialized that configuration's file inside its installation directory and
  ended by itself in 0.76 s with `Not configured`; nothing of it appeared under the host work
  directory. Under Docker, a plausible but nonexistent GitHub endpoint had the listener write
  `.runner` and `.credentials` and fail the connection with `The resource cannot be found`; the
  marker was in the runner's own argv and nowhere else the worker can see — not in the container's
  environment or command, not in the host work directory, not in the lease directory.
- **`--ulimit fsize` kills the listener** (`SIGXFSZ`, exit 153) at every value tried between 1 TiB and
  1 PiB and is fine only at `unlimited`, so a runner sandbox takes no file-size limit and a runner's
  disk has no quota mechanism yet.

Docker's `--user 1001:1001` stood in for Podman's `keep-id` in the Docker runs, since Docker has no
`keep-id`; the Podman runs used the real flag.

What none of that covers, because it needs the real hosts: **egress**, which is what runner mode runs
on — the Podman available to the build container has no `/dev/net/tun`, so every probe above ran with
`--network none` and `pasta` never started; that `podman unshare nsenter` loads the refusals into a
runner container's namespace, and that they hold against a real metadata endpoint and the real link
address; that a real just-in-time configuration takes exactly one job and the runner exits with the
job's result — a fake one can only show that the configuration is spent, written and ended by itself;
the cancel-from-GitHub and worker-crash drills; and arm64. Those are the AR03 suite's gate on
`reference-host` and `arm64-host` and its pilot workflow, and the pilots' measured restore and upload
times are the benchmark wave's. This release states the residual rather than claiming it.

The sandbox suite did run here, and it is no longer a skip: the image was built and pushed to a throwaway
registry on the build machine (`127.0.0.1:5000`, rootless Podman 4.9.3, 2026-11-20), pulled back by the
digest the script printed, and `runner_sandbox` passed both of its tests against that digest in 4.0 s —
the container created from the plan's own flags, the runner ending by itself, the container and the lease
directory gone afterwards, and the canary in neither the environment, the command line nor the work
directory.
