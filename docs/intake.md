# Event intake: ref updates, webhooks and durable resolution (G02/G03)

Part 05 starts two ways: a person or agent dispatches a pinned pipeline through
the [API](api.md), or a repository tells Sentinel that something changed. This
document is the second path. Intake is deliberately small: authenticate, bound,
store, acknowledge, and let a bounded lane resolve off the request path. No
route starts a container, fetches a pipeline or waits for a run.

Resolution has two phases, both on the same lane. **Validation** re-checks the
source binding and ref and settles the delivery as `ready`. **Dispatch** then
resolves the pipeline from the authorized repository at the policy-selected
pinned revision through Git, asks the compiled pipeline whether it admits the
event, and creates one immutable run — or settles an explicit outcome, which
becomes a GitHub Check when the repository is forge-associated
([checks](checks.md)).

## Two authenticated shapes, one store

| | Generic ref update | GitHub webhook |
|---|---|---|
| Route | `POST /api/v1/intake/{repo}` | `POST /api/v1/hooks/github` |
| Credential | per-repository hook secret (`Authorization: Bearer sentinel_hook_…`) | App webhook secret (HMAC-SHA256 over the raw body in `X-Hub-Signature-256`) |
| Identity | the relay's own stable delivery ID | `X-GitHub-Delivery` |
| Event | one ref transition (always `ref_update`) | `X-GitHub-Event` (`push`, `pull_request`; control events below) |
| Body limit | 64 KiB | 4 MiB |
| Enabled by | a bound source and an issued hook secret | `<data_dir>/github-webhook.json`; without it the route is `not_found` |

Both paths end in the same row: tenant-owned, deduplicated on
*(repository, provider, delivery ID)*, acknowledged with `202` only after the
writer transaction commits. A redelivery with identical terms is
`{"duplicate": true}` with the original record ID; the same identity with
different terms is `conflict`.

`POST /api/v1/intake/{repo}` body:

```json
{
  "delivery_id": "8f3e…",
  "ref": "refs/heads/main",
  "old_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "new_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
```

`ref` must be a full `refs/…` name, and both object IDs are 40- or 64-digit
lower-case hex. An all-zero `new_sha` is a deletion: accepted and stored like
any other transition, then resolved as `ignored:ref_deleted`.

A GitHub `push` keeps only the fields intake needs (installation ID, immutable
repository ID, ref, before/after). The delivery is attributed to the repository
of the *bound* App installation — the payload cannot name a tenant, and an
unbound repository is answered `200 {"ignored": "unbound_repository"}` so
GitHub does not retry it. Events this build does not handle at all are
acknowledged the same way: `{"ignored": "unsupported_event"}`.

### Control events

Five further signed events — `check_run`/`check_suite` rerequests,
`installation`, `installation_repositories` and `repository` lifecycle changes
— are **control**, not intake: they keep only bounded identifiers, are
receipted in `github_events` by delivery ID and content digest (a replay
replays the recorded outcome; a changed body is a `conflict`), and answer
`200 {"controlled": <outcome>}`. What they do — rerequest handling, revocation
and the durable refresh lane — is the reconcile contract in
[checks](checks.md#rerequests-and-lifecycle-reconciliation-g05).

### Pull requests

`pull_request` events are intake for the three actions that mean new work:
`opened`, `synchronize`, `reopened`. Every other action (labels, reviews,
closing) is answered `200 {"ignored": "pr_action"}` without a stored row.

The delivery records what Git refs cannot prove: its ref is the **base**
branch (`refs/heads/<base.ref>`, the branch whose policy the change targets).
The head branch, head repository, head tip, base tip and the merge commit the
payload claims are stored beside it (`pr_deliveries`, migration 19), so fork
provenance is a fact on record rather than an inference.

Trust is decided from those facts, and only those facts:

- the head repository must be the repository the binding points at; a
  different head repository is `ignored:fork_pr` — hostile fork execution is a
  later feature, never a default;
- an App association is required: a pull request for a repository bound
  without one is `failed:no_forge_association`;
- the payload's `merge_commit_sha` is a hint, never authority — GitHub may not
  have recomputed it when the event fires, and it can name a merge built for
  an *older* head. Resolution fetches the live `refs/pull/<n>/merge` ref and
  requires the commit it names to list the delivered head among its parents;
  an absent or still-stale ref is `merge_pending` and retried under the same
  attempt budget as a fetch fault, and a merge that never materialises
  settles `ignored:merge_unavailable`;
- the run checks out the **verified tested merge** and reads the pipeline
  from that same revision, so what runs is exactly what was proposed for the
  base branch — and provenance records the verified merge commit, not the
  payload's claim.

## Hook secrets

One active secret per repository, digest-only in `source_intake_tokens`
(BLAKE3), scoped to that repository: presenting a valid secret to another
repository's route is a 401, never a 403 that would confirm a relationship.
The secret is shown exactly once:

```sh
sentinel admin source hook-token --data-dir "$DATA" --repo rep_… > hook.secret
sentinel admin source hook-token --data-dir "$DATA" --repo rep_… --revoke
```

Issuing rotates in one transaction: the previous secret stops working the
moment it commits. Revoking the source binding (`admin source revoke`) deletes
the secret in the same transaction — a revoked repository receives nothing.

The secret is a bearer credential. Send it over TLS (the API itself speaks
plain HTTP behind the operator's reverse proxy) or over loopback.

## The post-receive hook and relay

`examples/hooks/post-receive` is a POSIX `sh` hook plus a `--flush` mode for a
cron/systemd timer. It never resolves a pipeline and never waits for CI:

- each `git push` line (`<old> <new> <ref>`) becomes one spooled file named by
  its delivery ID, written before the first attempt, so a retry is deduplicated
  by the controller and a replayed push cannot become a second run;
- delivery IDs sort by creation time (seconds, nanoseconds where `date`
  has `%N`, the hook's own sequence within one push, then randomness) and
  the hook globs in byte order, so the spool is always delivered **oldest
  first**: the hook spools the push's events behind anything already waiting
  and delivers the whole spool in order, and a transient failure stops the
  pass rather than letting newer events overtake it;
- a bounded `curl` (10 s, two retries) delivers each event; on failure the
  event stays in the spool and the push's stderr says so. The hook secret
  reaches curl as a config line on its standard input, never in its
  arguments, so it does not show in `ps` or `/proc/<pid>/cmdline`;
- `429` (the admission bound, a full writer queue, an ambiguous write) and
  `408` are the controller asking for a retry: the event stays spooled;
- `--flush` retries spooled events in the same order, files permanent
  refusals (other 4xx) under `failed/` with the HTTP status, counts attempts
  and moves an event to `failed/` after `SENTINEL_FLUSH_ATTEMPTS`;
- a full spool (`SENTINEL_SPOOL_MAX`) refuses new events loudly instead of
  growing without bound.

```sh
install -m 0755 examples/hooks/post-receive /srv/git/app.git/hooks/post-receive
install -m 0600 examples/hooks/sentinel-hook.env.example /srv/git/app.git/hooks/sentinel-hook.env
# edit the URL and the secret, then a systemd timer or cron runs:
/ srv/git/app.git/hooks/post-receive --flush
```

Uploading the hook to a host is an administrator's decision; Sentinel does not
install hooks into repositories. Providers with their own webhooks (Gitea,
Forgejo, GitLab) translate into the same generic route; native payloads are not
accepted here, and G08 verifies those fixtures.

## Ref polling (G07)

Repositories whose forge has no delivery mechanism — or where installing a
hook is not an option — can opt into bounded `git ls-remote` polling:

```sh
sentinel admin source poll --actor usr_… --repo rep_… \
    --interval 60s --refs 'refs/heads/main,refs/tags/v*'
```

The configuration is tenant-owned and requires a live binding: the remote,
credential and trust the poll uses are exactly the binding's, issued per poll
the same way resolution issues them. Ref selectors follow the binding's own
rules — exact refs under `refs/heads/` or `refs/tags/`, or one trailing
wildcard. Polling refs outside the binding's `allowed_refs` is permitted, but
the deliveries it produces settle `failed:ref_not_allowed`, exactly as a hook
reporting the same refs would.

**Initial discovery records a baseline and admits nothing**: enabling polling
never replays history. From then on, each advertisement is diffed against the
durable cursor and every transition becomes an ordinary `poll`-provider
`ref_update` delivery through the same `accept` a hook uses — validation,
dedup, `no_trigger` matching, resolution, dispatch, provenance and Checks are
unchanged:

- a ref that moved (including a force-push or a rewind) admits `old → new`;
- a newly advertised ref admits `zero → new`;
- a ref that disappeared admits `old → zero`, which resolves to
  `ignored:ref_deleted`;
- an annotated tag is tracked by its tag object id with the peeled commit
  recorded alongside — retagging is a move, and resolution peels the tag to
  its commit for checkout exactly as a hook-reported tag does.

The cursor and the deliveries it produced commit in one transaction, and a
transition's delivery ID is the digest of `(ref, old, new)` **and the cursor
state it moves** (the delivery that last moved the cursor, and when; the
admission time for a ref with no cursor): replaying an advertisement against
the same cursor is a no-op, while a legitimate repeat of a transition —
`A→B`, force-reverted `B→A`, re-pushed `A→B` — is a new delivery and is
built again. Nothing is acknowledged from memory.

**Budgets.** Each `ls-remote` runs under the same discipline as every Git
call — no prompts, no host configuration, a process group with a deadline
(20 s by default), credential helper files that exist only for the call, and
bounded, redacted diagnostics. Its output is byte- and count-capped (4,096
refs); a remote answering more is a bounded refusal, not a truncation. The
lane polls at most 8 due repositories per pass on a 250 ms tick — one thread,
no fan-out per ref — so a slow or hostile remote consumes only its own
schedule. Intervals run 10 s–24 h; a stable per-repository jitter of up to a
quarter of the interval, derived from the repository ID, keeps same-interval
repositories from synchronizing, including after a restart, since the
schedule is durable. A failed poll records `failures` and `last_error` (at
most 256 bytes, cut on a character boundary) and backs off exponentially
from the interval to a 15-minute ceiling; the next success clears it. The
same back-off parks a repository whose tenant is suspended
(`tenant_suspended`), whose installation no longer grants access
(`access_removed`) or whose remote the destination policy no longer approves
(`destination_refused`) — its configuration is kept for when that changes —
and a repository whose poll hits a store fault. No repository can stay first
in every pass: a pass never fails on one configuration, and a panic in a
pass costs a back-off, not the thread.

**Lifecycle.** `admin source show` reports the configuration and schedule;
`admin source poll --repo rep_… --disable` removes it. Rebinding (a possibly
different remote) and changing the ref selection both rebuild the baseline —
stale cursors cannot fabricate deletions — and revoking the binding removes
the configuration outright; a configuration that outlives its binding is
dropped the next time the lane sees it, never polled again.

**What polling is not.** An advertisement is a point-in-time snapshot: a push
that lands and is superseded between polls is never observed, so polling is
not an every-push guarantee and it is not the scheduler's dispatch clock —
the intake lane remains the only clock that turns deliveries into runs. Where
a forge can deliver events, prefer them for latency; polling exists so bound
repositories without one still get observed. Its cost is its own lane's and
shows up as `poll_observed` / `poll_failed` log events, measurable
independently of the intake lane.

## Resolution

The lane is one thread in the controller. It drains due deliveries in batches
of 64, woken immediately by an accepted delivery and otherwise by a 250 ms
tick. An idle tick is two index-backed reads (the `deliveries_open` index,
migration 34) and no write: the writer — and the commit that wakes every
parked run watch — is taken only when a pending delivery is due. Faults are
isolated per delivery: one whose resolution hits a store fault is parked
under its own retry schedule (`retried:store_fault`, same attempt budget) and
the pass continues, so one delivery can never hold every other tenant's work
behind it. Only a store that cannot even record that backs the lane off,
from 1 s to 30 s.

**Phase one, validation**, runs inside one writer transaction against the
binding **as it is now**:

| Outcome | Meaning |
|---|---|
| `ready` | The binding is active, the ref is allowed and the revision is not a deletion. |
| `ignored:ref_deleted` | A deletion or an event with no ref: understood, deliberately not a trigger. |
| `failed:binding_revoked` | The binding was revoked between acceptance and resolution. |
| `failed:tenant_suspended` | The repository's tenant was suspended. A store fault while checking is retried, never read as a suspension. |
| `failed:ref_not_allowed` | The binding no longer allows this ref. |

**Phase two, dispatch**, takes each ready delivery through bounded remote work
with no writer held — mint the source access (sealed credential, or a GitHub
App installation token rechecked against the binding's version afterwards),
read the pipeline file at the pinned revision, compile it, match the policy —
and ends in one short transaction. The pipeline file is read through Git at:

- the pushed revision for a branch or tag event (an annotated tag is peeled to
  its commit, which is what runs);
- the tested merge for a pull request.

The compiled `on:` policy decides whether the event is one this pipeline wants
(see the [pipeline schema](pipeline-schema.md)); a mismatch is
`ignored:no_trigger`, not an error.

| Outcome | Meaning |
|---|---|
| `dispatched:<run>` | One immutable run was created from the compiled pipeline at the exact revision. |
| `ignored:duplicate` | This ref transition was already dispatched. |
| `ignored:superseded` | The repository already moved past this push: the newest dispatched transition starts where it ended, or (for a branch) its revision is in the newest dispatched revision's history. |
| `failed:tenant_suspended`, `failed:binding_revoked`, `failed:access_removed` | The binding authorizes nothing any more: the tenant is suspended, the binding revoked (including a `repository` rename revoking an App binding), or the App installation suspended, deleted or without the permissions it needs. |
| `failed:destination_refused` | The deployment's `source-destinations.json` no longer approves the binding's remote; nothing was fetched. |
| `ignored:no_trigger` | The pipeline at that revision does not declare this event or ref. |
| `ignored:fork_pr`, `ignored:merge_unavailable` | Pull-request trust refusals (above). |
| `failed:no_pipeline` | The bound pipeline path does not exist at the revision. |
| `failed:pipeline_invalid` | It exists but does not load, decode or compile; the reason is logged. |
| `failed:image_unpinned` | A job's image is not digest-pinned; execution admission (K05) cannot resolve tags yet. |
| `failed:no_forge_association`, `failed:pr_metadata` | A pull request arrived without the association or terms that prove it. |
| `failed:source_unavailable` | No usable credential exists for the binding. |
| `retried:source_unreachable`, `retried:github_unavailable` | A transient fetch or provider fault; the delivery stays open and the same attempt budget applies. |
| `retried:source_changed`, `retried:store_unavailable`, `retried:store_fault` | The binding was rotated or changed between lookup and issuance, or the store was busy or faulted; the next attempt looks the binding up again. |
| `retried:merge_pending` | The pull request's merge ref is absent or still names a merge for an older head; GitHub may simply not have recomputed it yet, so the delivery stays open under the same budget. |
| `failed:resolution_attempts` | Repeated transient faults spent the attempt budget. |

Duplicate and reordered events are compared per stream: the newest dispatched
delivery for the same repository, ref and event class (ref updates and pull
requests are separate streams even when they share a base branch). Arrival
order is not push order — a relay replays its spool, GitHub documents
out-of-order delivery — so the rule is anchored on what was dispatched and on
commit history:

1. an identical transition is a duplicate;
2. a transition starting where the newest one ended continues the stream and
   runs — including a forced rewind and a repeat of an earlier transition;
3. a transition ending where the newest one began is superseded;
4. any other branch push is superseded when its revision is an ancestor of
   the newest dispatched revision. Resolution proves it through Git with only
   commits fetched (`--filter=tree:0`, at most 1024 generations back); a tip
   the remote no longer has, or an ancestor outside the window, proves
   nothing and the push runs.

So pushes `A→B`, `B→C`, `C→D` arriving as `C→D`, `A→B`, `B→C` build `D`
only; neither stale push dispatches, and under `cancel_in_progress` neither
can cancel the tip's run. The in-order case never touches Git for this (rule
2). Tags and pull requests stop at rule 3: a retagged tag is not history, and
one base branch's stream holds unrelated pull requests.

Every dispatched run records immutable provenance (`run_provenance`, migration
19): the trigger kind, the delivery and provider, the ref transition, the
pull-request head/base/merge revisions and number, the pipeline path and the
exact revision the pipeline was read at, and the compiled pipeline digest. The
worker's expression context is filled from it, so `event.name`, `event.ref`,
`event.key`, `event.base_ref` and `event.pr_number` are real values rather
than unresolved fields (see the [pipeline schema](pipeline-schema.md)).

Settled rows are terminal — the store's trigger refuses reopening one — and
each settlement is logged as `intake_settled` with its delivery and outcome,
and a failed batch as `intake_failed`. A settled delivery on a
forge-associated repository also queues the completed check its outcome owes
([checks](checks.md)); a dispatched run queues the aggregate and one check per
job in the same transaction that creates the run.

Admission is bounded: at most 1024 open deliveries per repository, after which
a new event is `429 rate_limited` (a duplicate is still acknowledged).
Retention is the operator's: `admin intake list --repo rep_… [--state …]`
shows the newest deliveries, and `admin intake purge --older-than 7d` deletes
settled rows that produced nothing, in bounded batches: never an open one, and
never one a run's provenance depends on. The same command retires GitHub
control-event receipts (`github_events`) by age under the same batch bound
(`receipts_purged` in its output), but never one younger than 30 days: a
receipt is what makes a replayed signed control event — a `repository`
rename that revokes a binding, say — a recorded no-op, and GitHub redelivers
for days. GitHub signatures carry no timestamp, so a push whose delivery
record was purged can be replayed; it is then judged by the ordering rule
above, which supersedes a push the branch already moved past.

## Configuration

| File | Purpose |
|---|---|
| `<data_dir>/github-webhook.json` | `{"secret": "…"}` (16–256 printable ASCII), owner-only. Enables the GitHub route. |
| `<data_dir>/source-destinations.json` | the deployment's approved authorities ([sources](sources.md)), read at start; resolution settles `failed:destination_refused` and polling backs off for a binding outside it, before anything is fetched |
| `<data_dir>/master.key` | seals source credentials ([sources](sources.md)); intake tokens are digests and need no key |
| `<data_dir>/intake-work/` | per-delivery scratch repositories for phase two; discarded and recreated on start |
| `<data_dir>/poll-work/` | per-repository scratch for poll credential helpers; discarded and recreated on start |
| `<data_dir>/github-app.json` | the App that authorizes source access **and** publishes Checks ([checks](checks.md)) |

## Verification

- `crates/sentinel-github` unit tests: raw-body HMAC exactness (a reformatted
  body fails), malformed headers, wrong keys, bounded push parsing, and
  pull-request parsing (null merge, fork head recorded, malformed pieces
  refused).
- `crates/sentinel-pipeline` tests and fixtures: the `on:` mapping form, ref
  pattern matching and its bounds, the digest changing with the policy.
- `crates/sentinel-git` tests: one file at one revision, annotated-tag
  peeling, missing/oversized/unsafe paths, and access that must match the
  remote and its expiry.
- `crates/sentinel-store/tests/intake.rs`: dedup and mismatch, malformed terms
  (including pull-request terms), the admission bound, digest-only
  rotatable/revocable secrets, GitHub targets through a bound installation
  only, every validation outcome, retry backoff and attempt exhaustion,
  retention purging settled history only, immutable terms and provenance
  through raw SQL, dispatch creating one run with its images and provenance,
  and the duplicate/superseded streams.
- `crates/sentinel-intake/tests/dispatch.rs` (Linux, needs `git`, `python3`,
  `openssl`): resolution over a real repository served on loopback HTTPS — a
  push dispatching with exact provenance, duplicate and superseded refusals,
  the policy refusing a branch, annotated-tag peeling, the explicit
  `no_pipeline`/`pipeline_invalid`/`image_unpinned` outcomes, an unreachable
  remote retrying to the attempt budget, a same-repository pull request
  dispatching at the tested merge through a stubbed App token flow, fork and
  unmergeable refusals, a generic binding refusing PR metadata, and a revoked
  binding.
- `crates/sentinel-intake/tests/dispatch.rs` also: non-adjacent out-of-order
  pushes superseded through Git ancestry with `cancel_in_progress` never
  cancelling the tip, and a forced rewind still running.
- `crates/sentinel-intake/tests/isolation.rs`: a suspended tenant, suspended
  installation or revoked App binding settling its own delivery while another
  tenant's dispatches; a store fault parking one delivery; the destination
  policy refusing before any fetch or listing; a rotation racing issuance
  retried; an idle lane taking no writes; a suspended tenant's poll backing
  off without blocking others; a multibyte failure reason bounded without
  killing the poll lane.
- `crates/sentinel-git/tests/ancestry.rs` (Unix, needs `git`): the ancestry
  window, force-pushed tips, and unauthenticated fetches refusing `ssh`,
  `git://` and plain `http://`.
- `crates/sentinel-intake/tests/flow.rs`: both ingest paths over a real store,
  including signature/tamper refusals, pull-request terms, and lane resolution
  on a wake and on the idle tick.
- `crates/sentinel-store/tests/poll.rs`: opt-in configuration under tenant
  authority and its bounds, the baseline-then-diff protocol, deterministic
  delivery identities across replays, creation/move/deletion transitions,
  annotated-tag tracking, the overloaded-queue deferral keeping its cursor,
  and rebind/revoke cleanup.
- `crates/sentinel-git/tests/ls_remote.rs` (Linux, needs `git`): real
  `ls-remote` exchanges — heads and tags with annotated peels, oversized
  advertisements, unreachable and option-shaped remotes.
- `crates/sentinel-intake/tests/poll.rs`: the lane end to end — an observed
  move becoming a delivery that dispatches a run, remote failures backing
  the schedule off, and a vanished binding retiring the configuration.
- `crates/sentinel-intake/tests/dispatch.rs` (above) also polls the real
  loopback remote through `GitLister`: baseline, transition, delivery,
  dispatch and provenance with no injected pieces.
- `crates/sentinel-api/tests/api.rs`: the routes over loopback — unscoped
  secrets, size limits, dedup, conflicts, ping, unbound and unsupported
  events, and pull-request actions.
- `crates/sentinel-intake/tests/relay.rs` (Linux, needs `git`, `sh`, `curl`): a
  real push through the example hook — delivery, spooling across a dead
  controller, stable IDs through `--flush`, permanent refusals under `failed/`,
  `429`/`408` kept spooled, spooled pushes delivered oldest first (also ahead
  of a live push), the secret never in curl's arguments, a full spool, and an
  unencodable ref refused without a spool write.
- `crates/sentinel/tests/intake_e2e.rs` (Linux, `server`): the real binaries —
  the server loads its webhook secret and destinations, accepts and
  deduplicates a ref update, validates the binding, resolves the pipeline from
  a repository served on loopback HTTPS, creates a run, logs
  `intake_settled` in order, and the CLI lists the durable record with its run,
  keeps it under retention while purging history that produced nothing.