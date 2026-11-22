# Fork pull requests: secret policy and the hostile-fork pool

A design that is **written, not built** ([open designs](designs.md)). It covers the owner decision X5 ([TODO](../TODO.md#owner-prerequisites)) and what I09 and M09 ([backlog](backlog.md)) would build once it is made. Nothing here changes v0.1: a fork pull request stays `ignored:fork_pr`.

## What the system does today

| Fact | Where |
|---|---|
| A `pull_request` whose head repository is not the bound repository is `ignored:fork_pr`; no run exists | `crates/sentinel-intake/src/resolve.rs`, [intake](intake.md#pull-requests) |
| A same-repository `pull_request` run from a signed delivery receives bound secrets; its pipeline file is read at the tested merge | [secrets](secrets.md#who-may-cause-a-delivery), [intake](intake.md) |
| Manual and polled runs never receive a secret | [secrets](secrets.md#who-may-cause-a-delivery) |
| Cache trust has three scopes, `protected`, `pull_request`, `unprotected`; each reads and writes only its own | [cache](cache.md#trust-derivation), `crates/sentinel-protocol/src/cache.rs` |
| Runner mode already has a tenant opt-in (`tenants.runner_fork_prs`) and a pool flag (`pools.fork_prs`, migration 76); a marked pool serves fork jobs only | [runner mode](runner-mode.md#fork-pull-requests) |
| A microVM has no network interface unless the worker sets `job_network = "egress"`; its scratch disk is an image of exactly the declared size; `/dev/kvm` is not exposed | [executor](executor.md#job-network), [plan 16.8](../plan.md#168-microvm-execution-on-kvm-hosts) |

Rootless containers share the host kernel and are not a boundary for hostile code ([plan](../plan.md)).

## The owner decision (X5)

The pipeline file of a pull-request run is read at the tested merge, so the author of a fork pull request writes the pipeline that runs. Whatever a fork run can read, its author can print.

| Option | What a fork PR gets | Cost | Risk |
|---|---|---|---|
| A. Refuse (today) | nothing; `ignored:fork_pr` | none | public repositories cannot take outside contributions through Sentinel |
| **B. Run, never with secrets** | a run on the hostile-fork pool, no secret of any kind, for repositories that opt in | I09 and M09 below | bounded by the pool's isolation; nothing of the tenant's is in reach |
| C. B, plus a maintainer may approve one fork head to run with secrets | as B until approved, then bound secrets for that exact head SHA | B, an approval surface, and a GitHub permission read that is unverified (X3: whether `members:read` can read a collaborator's permission) | a reviewer who misses one line in the diff leaks every bound secret; the approved run must leave the hostile pool, so the boundary no longer contains it |
| D. Treat like a same-repository PR | bound secrets | none | any GitHub account can read every secret bound to the repository |

**Recommendation: A for v0.1, then B.** D is not acceptable. C is the only option where a secret can reach code the tenant has not merged, it depends on X3, and the need it serves (a secret-bearing check on outside code) is met without it: merge the change to a branch of the repository, where the existing same-repository rule applies. C can be added on top of B later without changing B.

B leaves two smaller choices, with defaults taken here:

1. **A fork run whose job declares `secrets`, `secret_files` or `registry_auth`:** the job fails with a named reason (`fork_pr_secrets`), as a manual run's does (`manual_run_secrets`). The alternative, running it with the secret absent, hides the difference from the contributor and the maintainer.
2. **Egress:** off, as M09 states. A fork job then builds only from its image and the fork cache scope. A tenant that needs downloads would get them from the worker's read-only pull-through cache ([backlog](backlog.md), AR07), not from open egress, and that is a separate decision.

The same-repository rule is not part of X5 and is unchanged: anyone who can push a branch to the repository can already open a pull request whose run receives bound secrets.

## Design that follows from B

### Opt-in

- Per repository, on its binding: `fork_prs`, default off. The M09 gate is "a run only for repositories that opt in"; a tenant-wide switch would opt in private repositories that have no outside contributors.
- Enabling it is refused unless the tenant has a pool marked `pools.fork_prs`. The pool flag is the one runner mode uses; the two paths share the pool, not the opt-in (`tenants.runner_fork_prs` stays runner mode's).
- Audited like the runner-mode opt-in. A new column is a migration, and so changes under [compatibility](compatibility.md).

### Intake

- `resolve.rs`: when `pr.head_repo != bound_repo`, an opted-in repository gets a plan instead of `Ignored("fork_pr")`; every other repository keeps today's outcome.
- The run records `fork = true` in its provenance, derived from the stored `pr_deliveries` head repository, written once. A head repository the parser cannot read counts as a fork, as in runner mode.
- The merge-ref check is unchanged: the run tests `refs/pull/<n>/merge`, verified to have the delivered head as a parent.

### Secrets

- The delivery gate gains one condition: a run whose provenance says fork receives no secret, no `secret_files` and no `registry_auth`, whatever the delivery's authentication level. It fails closed the way the manual rule does, with a `use` audit row of result `denied`.
- The controller refuses at compile time (choice 1 above) so the job never reaches a worker.
- Source access: the credential that fetches the merge commit stays on the worker host and never enters the guest. A fork run on a private repository still needs it, so the failure test checks the guest's file system, environment and process list for it.

### Cache

A fourth trust value, `fork`. The existing `pull_request` scope cannot be reused: same-repository pull-request runs read it and receive secrets, so a fork that writes it could plant a dependency tree a secret-bearing run restores. `fork` reads and writes only its own scope; no other trust reads it. The trust byte is part of the worker protocol, so this is a protocol version bump, and an older worker is never offered a fork job (no downgrade exists that is safe).

### The pool (M09)

| Boundary | Rule | Enforced by |
|---|---|---|
| Separation | a fork run is demand only on a `fork_prs` pool; that pool takes no other run | placement's demand query, both directions, as runner mode does |
| Sandbox | microVM only; a worker whose executor is a container is never offered a fork job | capability bits the worker already states (M01) |
| Egress | none; a worker with `job_network = "egress"` cannot join a `fork_prs` pool | pool admission, and the scheduler's `egress` label |
| Nested KVM | `/dev/kvm` not exposed | unchanged default |
| Disk | the lesser of the job's `resources.disk` and the pool's ceiling | the scratch image is that size; a full disk is `ENOSPC` in the guest |
| Time | the lesser of the job's timeout and the pool's ceiling | the controller writes the bound into the run spec; the pipeline cannot raise it |
| Volume | a per-repository limit on concurrent fork runs; excess waits | admission |
| Artifacts and outputs | stored marked as a fork run's; no trusted run may consume them | the artifact store's boundary, as the runner-mode lease states trust |

The disk, time and concurrency ceilings are pool settings with no default proposed here: they need a measurement of the pilots' pull-request lanes on `kvm-host`.

### Failure tests (the gate)

One test per boundary, each failing when the boundary is removed:

1. A fork PR on a repository that did not opt in is `ignored:fork_pr`; opted in with no marked pool, the run waits and is never placed elsewhere.
2. A trusted run is never placed on the fork pool; a fork run never on a container worker or an egress worker.
3. A fork pipeline declaring a secret fails with `fork_pr_secrets`; a forged run spec that asks anyway is denied at delivery, with the audit row.
4. The source credential is absent from the guest.
5. A cache entry written by a fork run is a miss for `protected`, `pull_request` and `unprotected` runs, and the reverse.
6. From inside the guest: no interface, no `/dev/kvm`, `ENOSPC` at the disk ceiling, termination at the time ceiling with nothing of the VM left.
7. A trusted run cannot download a fork run's artifact.

The microVM tests run only on `kvm-host` ([CLAUDE.md](../CLAUDE.md#where-tests-run)).

## Needs before implementation

- The X5 decision.
- M04 and M05 verified on `kvm-host` (M09 depends on M05).
- The pool ceilings, measured.
- For option C only: X3.
