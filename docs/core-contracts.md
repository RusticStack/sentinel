# Core contracts (C01)

`crates/sentinel-core` defines the identifiers and the job/run state machine every Sentinel process shares. It is pure logic with one dependency (`uuid`), no allocation on any path, and one-byte enum representations, so the controller can evaluate a transition inside a SQLite transaction at the cost of a few comparisons.

## Identifiers

| Type | Prefix | Meaning |
|---|---|---|
| `UserId` | `usr_` | Human or tenant-bound service principal (A01); never a credential |
| `TenantId` | `tnt_` | Organization or personal namespace; root of every ownership check |
| `RepoId` | `rep_` | Repository binding inside a tenant, distinct from GitHub's numeric ID |
| `RunId` | `run_` | One compiled pipeline execution for one source revision |
| `JobId` | `job_` | One job of a run, immutable after compilation |
| `AttemptId` | `att_` | One execution attempt; reruns create new attempts |
| `WorkerId` | `wrk_` | Identity a worker generates at enrollment |
| `TokenId` | `tok_` | Handle for one issued API credential (A03); names the record, never the secret |
| `PoolId` | `pol_` | A worker pool, dedicated to a tenant or shared under explicit grants (A07) |
| `SessionId` | `ses_` | Handle for one browser session (A06); the cookie secret is separate |
| `InvitationId` | `inv_` | Handle for one invitation (A05); the redeemable secret is separate |
| `InstallationId` | `ins_` | One forge App installation; inactive until bound to a tenant (A05) |
| `StepIndex` | | `u16` position of a step inside its job |
| `Fence` | | `u64` per-job generation; `0` means never leased |

IDs are random UUID v4 stored inline as 16 bytes. Text form is `<prefix>_<canonical lowercase uuid>`, fixed length, and parsing rejects wrong prefixes, uppercase, non-v4 bytes and trailing characters. An ID grants nothing: every query joins through the tenant that owns the row.

A01 adds allocation-free roles, permission bit sets, credential scope bounds and borrowed namespace validation in `auth`. Live database authorization is documented in [Authorization](authorization.md); the state-machine `Actor` below is a separate controller/worker transition contract.

Each lease strictly increments the job's fence. A worker presents its fence with every event; a fence that is not the current one is rejected before the transition table is consulted, so a paused-then-resumed worker, a duplicate acknowledgement or a replayed completion can never touch a newer attempt.

## Job states and events

States: `blocked -> queued -> leased -> preparing -> running -> finalizing -> terminal(outcome)`.

Outcomes, in aggregation precedence from lowest to highest: `passed`, `skipped`, `canceled`, `timed_out`, `failed`, `infra_failed`. `passed` and `skipped` count as success.

| Event | Allowed actor | From | To |
|---|---|---|---|
| `DependenciesSatisfied` | controller | blocked | queued |
| `Skip` | controller | blocked, queued | skipped |
| `CancelBeforeStart` | controller | blocked, queued | canceled |
| `QueueTimedOut` | controller | blocked, queued | timed_out |
| `Leased(fence)` | controller | queued | leased (fence must increase) |
| `OfferLapsed` | controller | leased | queued (fence unchanged; the attempt was declined or never acknowledged) |
| `PreparationStarted` | worker | leased | preparing |
| `StepsStarted` | worker | leased, preparing | running |
| `FinalizationStarted` | worker | preparing, running | finalizing |
| `Passed` | worker | finalizing | passed |
| `Failed(class)` | worker | leased … finalizing | outcome of the class |
| `LeaseExpired` | controller, reconciler | leased … finalizing | infra_failed |
| `WorkerLost` | controller, reconciler | leased … finalizing | infra_failed |
| `Reconciled` | reconciler | leased … finalizing | infra_failed |
| `Rerun` | controller | any terminal, cancel not requested | queued (fence unchanged) |

Anything else is rejected without changing state: `Forbidden` (wrong actor), `StaleFence`, `Invalid` (no such edge), or `AlreadyTerminal` (terminal states absorb every event except a controller `Rerun`, which lets callers treat duplicate completions as idempotent acknowledgements). `OfferLapsed` returns an unacknowledged lease to the queue without rewinding the fence, so the lapsed attempt's worker is stale in every direction and the next lease strictly advances. `Rerun` is the only exit from terminal: it re-queues the job under the same compiled spec without touching the fence, so the next lease advances it and a late report from the previous attempt is stale. A cancelled job cannot be rerun. The tests enumerate every state, event and actor combination and assert the machine never panics and never mutates on error.

## Failure classes

Each class maps to exactly one outcome, so storage can never hold a contradictory pair:

| Outcome | Classes |
|---|---|
| failed | `command_failed`, `command_signaled`, `out_of_memory` |
| timed_out | `execution_timeout`, `queue_timeout` |
| canceled | `canceled` |
| infra_failed | `preparation`, `lease_expired`, `worker_lost`, `reconciled`, `publication`, `runtime` |

`runtime` (W04) is the container runtime failing to run a step — the exec never started or the runtime errored — as opposed to the command failing. `infra_failed` is never attributed to the repository and is what the CLI, GitHub check and MCP diagnostics distinguish from a real test failure.

## Cancellation

Cancellation is durable desired state on the job (`cancel_requested`), set once and never cleared. If the job is `blocked` or `queued`, the controller finishes it immediately with `CancelBeforeStart`. If a worker owns it, the flag is delivered on the session; the worker terminates the process group gracefully, then forcibly after the grace period, and reports `Failed(Canceled)` with its fence. If the worker never reports, lease expiry produces `infra_failed` and the flag still prevents any rerun from starting. Superseded runs, tenant suspension and operator cancel all use this one path.

## Run aggregation and dependencies

Run state is derived, never stored as truth: recomputed from the job rows in the transaction that changed a job. It is `pending` until any job is worker-owned, `active` while any job is unfinished, and terminal once every job is terminal, taking the highest-precedence outcome; a run whose jobs were all skipped is `skipped`.

Dependency policies: `on_success` (default) starts when the upstream passed or was skipped, `always` starts on any outcome except canceled, `on_failure` starts on failed, timed out or infra-failed. A non-terminal upstream means keep waiting; a false decision skips the dependent.

## Timestamps

`UnixMillis` is UTC wall-clock provenance in signed 64-bit milliseconds. `AttemptTimestamps` records when the controller committed entry into each state, first entry wins, so reordered or duplicated messages cannot move a time later. No duration is ever computed from two of these; monotonic nanosecond fields carry latencies, as the runtime foundations contract requires.

## What C02 builds on this

Tables persist `state` and the outcome as one-byte codes, `fence` as an integer, `cancel_requested` as a flag, and the timestamp columns above. Every transition is `UPDATE … WHERE id=? AND state=? AND fence=?` with the new values from `JobControl::apply`, which is the compare-and-set that makes the fence meaningful.
