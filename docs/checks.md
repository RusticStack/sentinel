# GitHub Checks outbox (G04)

A native GitHub run is only useful if the pull request says what happened. This
document is the delivery contract: what a run publishes, how a delivery
survives an outage or a rate limit, which conclusions GitHub sees, and how a
check that belongs to a superseded revision can never be written over.

The store owns the queue ([`sentinel-store::checks`](../crates/sentinel-store/src/checks.rs));
`sentinel-checks` owns check delivery through the `sentinel-github` API client.
Nothing in dispatch waits on a check: a run is created and scheduled whether or
not GitHub is reachable.

## What is published

| Check | Name | When |
|---|---|---|
| Aggregate | `sentinel / ci` | Every event-driven run of a forge-associated repository (push, tag, pull request) |
| Per job | `sentinel / <job>` | One per compiled job, from run creation to its terminal outcome |
| Refused event | `sentinel / ci` | An event that was understood but produced no run |

Names are stable on purpose: a repository protects `sentinel / ci` as a
required check, and it must mean the same thing on every run. Per-job checks
are namespaced so a required aggregate is never satisfied by a partial run.

A **manual** run publishes nothing at all. Its inline pipeline is an
operator's diagnostic, and the plan is explicit that a manual focused run must
never satisfy the full acceptance aggregate; named pipelines (Part 16) will
give manual and scheduled runs their own scopes.

A **settled delivery** still owes an answer when the event was a real trigger
but nothing could run: `failed:no_pipeline`, `failed:pipeline_invalid`,
`failed:image_unpinned`, `failed:source_unavailable` and the other permanent
outcomes publish a **completed** `sentinel / ci` so a required check does not
stay pending forever. `ignored:no_trigger`, `ignored:fork_pr` and
`ignored:merge_unavailable` publish a completed check with the **neutral**
conclusion ("not executed", with the reason). `ignored:duplicate`,
`ignored:superseded` and `ignored:ref_deleted` publish nothing: the transition
already has a check (or no commit exists), and a second one would impersonate
it.

Tag pushes publish from the peeled commit once a run exists; a tag *resolution
failure* publishes nothing, because a tag object is not a commit a check can
attach to.

## States, conclusions and details

A check's status is `queued` → `in_progress` → `completed`; only the last
carries a conclusion. The mapping is one-to-one with Sentinel's outcome
vocabulary:

| Job outcome | Conclusion |
|---|---|
| passed | `success` |
| skipped (a dependency did not pass) | `skipped` |
| canceled | `cancelled` |
| timed out (execution or queue) | `timed_out` |
| failed (command, signal, OOM) | `failure` |
| infrastructure failure (preparation, runtime, lease expired, reconciled) | `failure`, with the class named in the output |

The aggregate is the run's own aggregate (`sentinel-core`'s precedence:
infra failure > failed > timed out > canceled > passed; all-skipped is
`skipped`) and its output summarises `n/m jobs passed · …`.

`details_url` is `<public_url>/#/runs/<run id>` when the deployment configures
a public URL; the first page serves that hash route (and re-opens the run after
sign-in). A check that belongs to no run — a refused event — has no link, and a
deployment without `public_url` publishes checks without one.

Each check carries `external_id = sentinel:<run id>:<aggregate|job id>` (or
`sentinel:dlv:<delivery id>`), which is what G05's rerequests resolve back to a
run, and what reconciles a create GitHub accepted that we never recorded.

## Durable delivery

One outbox row per (run, scope) — or per refused delivery — holds the *desired*
state, coalesced: a job that moves queued → running → passed bumps a sequence
three times, and the row always holds the newest generation. The lane is one
bounded thread that:

1. reads due rows (pending, next attempt due), oldest first;
2. hands each to the publisher **outside any database transaction**;
3. writes the outcome back in a short transaction, guarded by the sequence it
   read.

Retries, refusals and rate limits are explicit:

- **transient** (a transport failure, a GitHub 5xx): the row is scheduled again
  with doubling back-off from one second to five minutes, inside an attempt
  budget of eight; the budget's exhaustion settles the row as refused with
  `attempts`;
- **rate limit** (403/429 with `Retry-After`, or `X-RateLimit-Remaining: 0`
  with a reset): the whole lane pauses until the reset (at most one hour,
  slept in bounded pieces so shutdown stays prompt) and the current generation
  is scheduled for the same time; a 429 without timing headers pauses for one minute;
- **permanent** (403 without rate-limit evidence, update/create 404, 422): the row records the
  bounded reason and is not retried. A later state change starts a fresh
  generation and tries once more;
- **token expiry**: a 401 drops the cached repository token and retries; the
  next attempt mints a new one. Repeated 401s exhaust the same eight-attempt budget.

Delivery is at-least-once per generation with idempotent writes: a repeated
attempt updates the same check run instead of creating another one.

Delivery retention preserves events referenced by publications, including
settled publications, so their durable identities remain available for G05.

### Stale writes never win

The row's guarded write names the sequence the publisher read. If the desired
state moved while the request was on the wire, the newer generation stays
pending and is published next; the older payload is never written over it. The
check run's numeric handle is recorded **regardless**, so the follow-up is an
update of the same check run — the reason "reconcile ambiguous API timeouts
before creating duplicates" is a rule, not a hope: before creating a check run
the publisher asks GitHub for a run on that commit with our name and adopts the
one carrying our `external_id`, which covers a create whose response was lost.

A late completion from a superseded attempt cannot reach GitHub at all: the
store's job fence refuses the report before any check row moves.

## Configuration

`<data_dir>/github-app.json` (owner-only, read at startup):

```json
{
  "app_id": 1234,
  "private_key_file": "/etc/sentinel/github-app.pem",
  "public_url": "https://ci.example.com",
  "api_url": "https://api.github.com"
}
```

- `public_url` (optional) is the deployment-facing base URL used for
  `details_url`; absent means checks carry no link.
- `api_url` (optional) overrides the GitHub API endpoint, for example for a
  test stub. Repository clone URLs currently remain GitHub.com URLs. HTTP is
  accepted only for a loopback host.

The lane runs only when a GitHub App is configured; pending publications remain
durable if the App configuration is removed. The App's checks
token is minted per repository with `permissions: {"checks":"write"}` — never
the wider source token — and cached until it is close to expiring. The cache
holds at most 1024 repository tokens, evicting the earliest expiry at capacity.

## Verification

- `crates/sentinel-store/tests/checks.rs`: the stable aggregate and one check
  per job, transitions moving both, manual runs publishing nothing, a settled
  event's completed check (and the outcomes that publish nothing), revoked
  bindings and tag objects, retry/backoff/exhaustion, stale generations and the
  recorded handle, identity immutability and ownership.
- `crates/sentinel-github` unit tests: repository-path parsing, payload bounds,
  conclusion/status parsing and the exact
  permission set of a checks token.
- `crates/sentinel-checks/tests/delivery.rs` (loopback stub, real store, real
  lane): creation with `details_url` and one cached token, updates ending in
  the right conclusions, adoption after an ambiguous create, a rate-limit
  pause and successful retry for both 403 and 429, a 401 token refresh, a permanent 422 refusal
  (recorded and not retried), a revoked binding refusing without a request, a
  settled delivery's completed check, and a prompt lane stop.
- `crates/sentinel/tests/intake_e2e.rs` (Linux, real binaries): the controller
  loads `github-app.json` with a stub endpoint, refreshes and binds an
  installation, accepts a signed fork pull request, refuses it as
  `ignored:fork_pr` and publishes a completed neutral `sentinel / ci` on the
  delivered revision; the CLI shows the durable delivery.

Live GitHub App, required-check and rerequest verification is G06; rerequest
handling is G05.
