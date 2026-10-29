# GitHub Checks outbox

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
operator's diagnostic, and a manual focused run must never satisfy the full
acceptance aggregate.

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

### Details link contract

`details_url` is built by one function (`sentinel_checks::details`) from a
configured base and a fixed route table. The base is the `public_url` of
`github-app.json` when set, otherwise the server's `public_url`
([configuration](configuration.md)); it is the origin the web interface answers
on. A deployment with neither publishes checks without a link, never a guess.

| Check kind | `details_url` |
|---|---|
| Run aggregate (`sentinel / ci`) | `<base>/runs/<run id>` |
| Per-job check (`sentinel / <job>`) | `<base>/runs/<run id>?job=<job id>` |
| Refused delivery (belongs to no run) | none |

The contract with the web interface, which is its own process and may be
rebuilt without touching the controller ([web interface](web-ui.md)):

- `GET /runs/<run id>` is served for as long as links to it may exist in
  GitHub, which keeps them forever. A signed-out visitor is asked to sign in and
  then returned to the page; a visitor without access gets the same refusal as
  for any run.
- `job` is advisory. A page that does not highlight the job still shows the
  whole run, so ignoring it is correct; an unknown value is ignored too.
- Only these two shapes are promised. A change to either is a change to this
  contract and needs a redirect from the old shape, because a completed check
  is never updated again and keeps the link it last published.
- The controller serves no human page of its own, so the base must be the
  web interface's origin, not the API listener's, when the two differ. The
  older `<base>/#/runs/<run id>` form still opens the run in the interface that
  was current when it was published.

`cargo test -p sentinel-checks` covers the URL built for each kind (aggregate,
job, refused delivery, unrecognised scope, no or empty base) and the lane's
published bodies.

Each check row has a stable id `sentinel:<run id>:<aggregate|job id>` (or
`sentinel:dlv:<delivery id>`), and every create sends it suffixed with the
generation that performed the create — `sentinel:<run id>:<scope>:<seq>`,
recorded as `create_seq` (migration 33) — so each create names exactly one
GitHub run. Updates keep sending the identity the run was created with. That
identity is what rerequests resolve back to a run (a bare legacy id still
matches rows created before migration 33), and what reconciles a create
GitHub accepted that we never recorded. The
forge's suite handle (`check_suite.id`) is stored beside the check-run handle
so a suite rerequest can find every publication of a run.

## Durable delivery

One outbox row per (run, scope) — or per refused delivery — holds the *desired*
state, coalesced: a job that moves queued → running → passed bumps a sequence
three times, and the row always holds the newest generation. The lane is one
bounded thread that:

1. reads due rows (pending, next attempt due), oldest first;
2. hands each to the publisher **outside any database transaction**;
3. writes the outcome back in a short transaction, guarded by the sequence it
   read.

The lane does not poll for publications. When nothing is due it sleeps on the
store's commit notifier and the earliest of the next pending row's retry time
(`checks::next_due_ms`, one read of the head of `check_publications_due`) and
its monotonic re-arm deadline: a new publication is read when its transaction
commits — at once after a quiet spell, at most once per 50 ms under unrelated
write load — and a backed-off row exactly when it is due. `Config::idle` (2 s by
default) is only the longest sleep without a read, the net for a write the
notifier cannot see, such as one from another process on the same database.

Retries, refusals and rate limits are explicit:

- **transient** (a transport failure, a GitHub 5xx): the row is scheduled again
  with doubling back-off from one second to five minutes, inside an attempt
  budget of eight; the budget's exhaustion settles the row as refused with
  `attempts`. A **completed** check is the final status a required check gates
  on, so it gets a longer budget: forty attempts with the ceiling raised to
  fifteen minutes, which rides out an outage of about seven and a half hours;
- **exhausted final status**: a completed check refused with `attempts` is put
  back in the queue with a fresh budget at lane start and then once per
  `Config::rearm_interval` (one hour by default). Each pass is bounded to 1000
  rows settled within the last seven days and schedules its next monotonic
  deadline even if the store write fails, so publisher recovery needs no
  restart and a re-arm failure cannot hot-loop;
- **rate limit** (403/429 with `Retry-After`, or `X-RateLimit-Remaining: 0`
  with a reset): GitHub limits per installation, so only that installation is
  parked. Its rows are deferred until the reset (at most one hour) **without
  spending an attempt**, and every other installation keeps publishing; a 429
  without timing headers parks for one minute. A repository whose installation
  is not known yet carries the scope `u64::MAX`, which never equals a real
  installation id, so it is never held back by another installation's limit
  (a scope of 0 would throttle unrelated installations);
- **poison rows**: `checks::due` isolates an undecodable row by its raw durable
  ID, and the lane defers it for an hour without trusting its other columns;
  healthy rows in the batch still publish. A row whose outcome cannot be written
  (the store rejects the update three passes in a row) is also parked for an
  hour instead of retried at the head of the queue, so one bad row never blocks
  other checks or tenants. Transient store faults back off the lane without
  counting toward a row's quarantine. A generation that moved under the
  publisher is simply re-read;
- **permanent** (403 without rate-limit evidence, update/create 404, 422): the row records the
  bounded reason (never empty; a blank GitHub message is recorded as
  `invalid request`) and is not retried. A later state change starts a fresh
  generation and tries once more;
- **token expiry**: a 401 drops the cached repository token and retries; the
  next attempt mints a new one. Repeated 401s exhaust the same eight-attempt budget.

Delivery is at-least-once per generation with idempotent writes: a repeated
attempt updates the same check run instead of creating another one.

Delivery retention preserves events referenced by publications, including
settled ones, so their durable identities remain available.

### Stale writes never win

The row's guarded write names the sequence the publisher read. If the desired
state moved while the request was on the wire, the newer generation stays
pending and is published next; the older payload is never written over it. The
check run's numeric handle is recorded **regardless**, so the follow-up is an
update of the same check run.

A create is ambiguous by nature: the request can land while its answer never
does. The durable answer to that is `create_started_ms`, written **before** the
create request goes out. A first attempt skips the lookup entirely — no mark
means no remote run can exist that we started — and a retry after a lost
answer finds the mark, asks GitHub for a run on that commit carrying the
outstanding create's identity, and adopts it instead of creating a second —
**whatever its status**. Many first creates are already `completed` (a
settled delivery's aggregate, a job that finished before its first
publication); because the identity carries the create's generation, an exact
match can only be the run that create made, never an older generation's
terminal run, so adopting it is safe and a lost answer never produces a
duplicate. A row created before migration 33 keeps the old rule for its
bare id: only a live run is adopted. The lookup is paged (100 runs a page,
at most ten pages, each answer bounded to 1 MiB), so a commit with many
reruns neither overflows one bounded answer nor hides the run past the first
page. A check run that has vanished during the lookup is reported as refused
(`lookup: …`), never recreated under the same name, because recreating it would
publish a duplicate on the forge. A crash between the
mark and the request costs one harmless lookup; a crash after the request is
what the mark exists for. An update is idempotent, so an ambiguous *update*
needs no mark: the next attempt updates the same run again.

A completed remote run being immutable shapes new generations too: when a
desired generation follows a publication whose last delivered status was
`completed` — a rerun, a rerequest, a retried check — the stored
`check_run_id` is cleared on the upsert — together with the create mark —
so the publisher *creates* a fresh check run, under the new generation's
identity, instead of PATCHing or adopting a dead one. The run's in-progress
phase is then visible on GitHub.

"Delivered" is what the store recorded, not what the previous desired state
was. A completed generation that never reached GitHub (it is still pending or
backing off) leaves the remote run live, so the handle and create mark are
kept and the next attempt updates that run; dropping them would orphan an
in-progress run and create a duplicate.

Recording the desired state is idempotent: a draft whose status, conclusion,
title and summary equal the stored ones changes nothing — the generation, the
retry schedule and the delivery cursor stay put — so a re-record cannot restart
a backing-off row or re-send what GitHub already has. A *refused* row is the
exception: a fresh event for it re-arms it.

A late completion from a superseded attempt cannot reach GitHub at all: the
store's job fence refuses the report before any check row moves.

## Rerequests and lifecycle reconciliation (G05)

GitHub sends control events on the same signed webhook: `check_run` and
`check_suite` `rerequested`, `installation` lifecycle, `installation_repositories`
grants, `repository` identity changes and, for a GitHub-backed organization,
the membership events `organization`, `membership`, `member` and `team`
([GitHub sign-in](github-sign-in.md#github-backed-organizations)). They are not deliveries and never
queue a ref update: each is receipted in `github_events` (keyed by delivery ID
with a SHA-256 digest over the event name and raw body), answered `200
{"controlled": <outcome>}`, and a replay answers the recorded outcome while a
changed body under the same delivery ID is a `conflict`. The parsing keeps
only bounded identifiers; a body never confers a grant — positive-looking
changes only enqueue durable refresh work.

A **rerequest** resolves through the publications themselves: a check-run
rerequest must match both the stored check-run handle and its `external_id`,
and a suite rerequest matches the stored suite ID, with a legacy `NULL` suite
still resolving when the run is otherwise eligible. Only a terminal,
non-superseded run of the still-bound repository reruns, as a full immutable
DAG reset — attempts, fences and image pins are preserved, the run's own
cancel flag clears with the jobs', jobs return to
queued/blocked (a job with an `if` is blocked and decided again against the
run's event), and fresh check desired state is recorded in the same
transaction. Because the reset follows a completed generation, every stored
handle is cleared (above), so the rerequest surfaces as **new** check runs —
and a second rerequest sent against the old, superseded check-run handle no
longer resolves to the active generation: it is `unknown_check`, never a
double rerun. Candidates are capped at 64; more is `rerequest_limit`, never
an unbounded fan-out.

**Lifecycle events** disable first and verify after. A deletion or suspension
event disables issuance immediately; an access removal, rename, transfer,
deletion or archival revokes the binding in the receipt transaction —
credential destroyed, version bumped. The reconcile lane
(`sentinel-checks::reconcile`) then drains `github_refresh`, a durable queue
of installation (kind 0) and repository (kind 1) passes seeded at startup,
scheduled by control events and re-due every five minutes. Each pass reads its
target, calls the GitHub API **outside** the writer, and commits the answer
fenced on the row's sequence — a stale pass can never overwrite a newer
schedule.

- Kind 0 applies an authenticated installation snapshot through the same
  `sources_forge::refresh` a binding flow uses (lifecycle-version fenced), then
  reconciles the bound repository set against the installation's actual list:
  a repository no longer granted, renamed, transferred or archived loses its
  binding. The list is paged to a bound of ten pages; a truncated list proves
  membership, never absence.
- Kind 1 verifies one binding's repository ID, owner account and exact clone
  URL; anything but an exact match revokes.
- A verified installation 404 disables it and revokes every binding that
  trusted it — a reinstalled App is a new identity. Every other failure is
  transport-class: retried under bounded back-off, never a revocation.
- **Revocations are fenced on the binding's version.** The pass reads the bound
  set with each binding's version *before* it asks GitHub, and the revocation
  applies only while the binding still has that version: a repository rebound
  between the read and the write keeps its new binding, and the next periodic
  pass judges it afresh.
- **A poison row cannot spin the lane.** Every pass outcome moves the row's
  `next_ms` into the future. A target the store cannot decode (a corrupt
  binding blob) is parked under the retry back-off like any failed pass, and
  after twelve failures the row waits an hour between attempts; a pass that
  could not record its outcome at all backs the lane off instead of picking the
  same row again at once.

A rerequest resets each job with a compare-and-set on the full terminal state,
fence and cancellation snapshot it just read; the run cancellation flag is
cleared with the same snapshot discipline. Any stale snapshot is `Conflict` and
rolls back the receipt, so a moved job or a newer cancellation is never
overwritten.

**Receipt retention.** A control-event receipt is kept at least 30 days
whatever retention an operator asks for, then purged. A signed delivery
replayed after that is processed again, which is accepted deliberately:
GitHub redelivers for days, not months; a replayed lifecycle event only
enqueues an authenticated refresh or revokes (the safe direction, and the next
pass re-verifies); and a replayed rerequest reruns at most the newest terminal
run of a ref (older runs are `active_or_superseded`), within the 64-candidate
cap. Keeping receipts forever would trade an unbounded table for protection
against a captured signed payload whose replay can only do the above, so the
bound stays.

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
  `details_url` ([contract](#details-link-contract)); absent falls back to the
  server's own `public_url`, and without either checks carry no link.
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
  recorded handle, identity immutability and ownership, the completed-check
  budget and re-arming, a throttle parking without spending an attempt,
  idempotent re-records and handle retention until a completed state is
  delivered, and a blank refusal reason stored as a non-empty one.
- `crates/sentinel-checks/tests/lane.rs`: a retry or throttle that exhausts the
  budget reported as refused, an exhausted final check re-armed and published
  after publisher recovery on the same live lane, a throttle parking rows without spending
  attempts, one throttled scope not stopping the others, and a row whose store
  writes keep failing quarantined without blocking the lane, a publication
  committed to an idle lane (safety re-read two minutes away) delivered by the
  commit notifier, a backed-off row read at its deadline with no commit to wake
  the lane, and an idle lane dropped promptly.
- `crates/sentinel-github` unit tests: repository-path parsing, payload bounds,
  conclusion/status parsing and the exact
  permission set of a checks token.
- `crates/sentinel-checks/tests/delivery.rs` (loopback stub, real store, real
  lane): creation with `details_url` and one cached token, updates ending in
  the right conclusions, adoption after an ambiguous create, a create whose
  remote effect landed while its answer was dropped — reconciled by external
  ID with the durable `create_started` mark — a lost answer to a create made
  already `completed` adopted with exactly one POST, adoption past a first
  page larger than 64 KiB, a rate-limit
  pause and successful retry for both 403 and 429, a 401 token refresh, a permanent 422 refusal
  (recorded and not retried), a revoked binding refusing without a request, a
  settled delivery's completed check, and a prompt lane stop.
- `crates/sentinel-store/tests/github_events.rs`: receipt replay and
  changed-body conflict, check-run and suite rerequests requeueing only a
  terminal non-superseded run (legacy `NULL` suite rows included), a canceled
  previously leased run keeping its attempt history and advancing its fence on
  the next lease, the candidate cap, unbound/revoked refusals, installation
  disable and repository-set revocation with credentials destroyed, refresh-row
  sequence fencing, and a confirmed 404 revoking everything. Store unit tests
  cover stale job-fence and cancellation snapshots conflicting.
- `crates/sentinel-checks/tests/reconcile.rs` (loopback stub): the refresh
  lane verifying a healthy installation and repository, revoking on rename,
  removal and a changed clone URL, disabling on a verified 404, keeping a
  suspended installation disabled until the API clears it, and retrying a
  transient 500 without revoking.
- `crates/sentinel/tests/intake_e2e.rs` (Linux, real binaries): the controller
  loads `github-app.json` with a stub endpoint, refreshes and binds an
  installation, accepts a signed fork pull request, refuses it as
  `ignored:fork_pr` and publishes a completed neutral `sentinel / ci` on the
  delivered revision; the CLI shows the durable delivery.

## Delivery latency bench

`crates/sentinel-checks/examples/checks-lane-bench.rs` times a run's queued checks from the start of the write that enqueues them to their arrival at a fake GitHub endpoint, with the real lane and publisher ([benchmarking](benchmarking.md#checks-lane-delivery-latency)). No record is committed yet, so this document states no latency figure.
