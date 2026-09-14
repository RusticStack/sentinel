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
event, and creates one immutable run — or settles an explicit outcome and, for
a GitHub-associated delivery, the outcome G04 turns into a Check.

## Two authenticated shapes, one store

| | Generic ref update | GitHub webhook |
|---|---|---|
| Route | `POST /api/v1/intake/{repo}` | `POST /api/v1/hooks/github` |
| Credential | per-repository hook secret (`Authorization: Bearer sentinel_hook_…`) | App webhook secret (HMAC-SHA256 over the raw body in `X-Hub-Signature-256`) |
| Identity | the relay's own stable delivery ID | `X-GitHub-Delivery` |
| Event | one ref transition (always `ref_update`) | `X-GitHub-Event` (`push`, `pull_request`) |
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

### Pull requests

`pull_request` events are intake for the three actions that mean new work:
`opened`, `synchronize`, `reopened`. Every other action (labels, reviews,
closing) is answered `200 {"ignored": "pr_action"}` without a stored row.

The delivery records what Git refs cannot prove: its ref is the **base**
branch (`refs/heads/<base.ref>`, the branch whose policy the change targets)
and its revision is the tested **merge** commit GitHub computed, falling back
to the head tip when there is none. The head branch, head repository, head tip
and base tip are stored beside it (`pr_deliveries`, migration 19), so fork
provenance is a fact on record rather than an inference.

Trust is decided from those facts, and only those facts:

- the head repository must be the repository the binding points at; a
  different head repository is `ignored:fork_pr` — hostile fork execution is a
  later feature, never a default;
- an App association is required: a pull request for a repository bound
  without one is `failed:no_forge_association`;
- a pull request without a tested merge is `ignored:merge_unavailable`: there
  is nothing truthful to check out;
- the run checks out the **tested merge** and reads the pipeline from that same
  revision, so what runs is exactly what was proposed for the base branch.

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
- a bounded `curl` (10 s, two retries) delivers it; on failure the event stays
  in the spool and the push's stderr says so;
- `--flush` retries spooled events, files permanent refusals (4xx) under
  `failed/` with the HTTP status, counts attempts and moves an event to
  `failed/` after `SENTINEL_FLUSH_ATTEMPTS`;
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

## Resolution

The lane is one thread in the controller. It drains due deliveries in batches
of 64, woken immediately by an accepted delivery and otherwise by a 250 ms
tick; store failures back off from 1 s to 30 s.

**Phase one, validation**, runs inside one writer transaction against the
binding **as it is now**:

| Outcome | Meaning |
|---|---|
| `ready` | The binding is active, the ref is allowed and the revision is not a deletion. |
| `ignored:ref_deleted` | A deletion or an event with no ref: understood, deliberately not a trigger. |
| `failed:binding_revoked` | The binding was revoked (or the tenant suspended) between acceptance and resolution. |
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
| `ignored:superseded` | The newest dispatched transition of this ref starts where this one ended: the repository moved past it. |
| `ignored:no_trigger` | The pipeline at that revision does not declare this event or ref. |
| `ignored:fork_pr`, `ignored:merge_unavailable` | Pull-request trust refusals (above). |
| `failed:no_pipeline` | The bound pipeline path does not exist at the revision. |
| `failed:pipeline_invalid` | It exists but does not load, decode or compile; the reason is logged. |
| `failed:image_unpinned` | A job's image is not digest-pinned; execution admission (K05) cannot resolve tags yet. |
| `failed:no_forge_association`, `failed:pr_metadata` | A pull request arrived without the association or terms that prove it. |
| `failed:source_unavailable` | No usable credential exists for the binding. |
| `retried:source_unreachable`, `retried:github_unavailable` | A transient fetch or provider fault; the delivery stays open and the same attempt budget applies. |
| `failed:resolution_attempts` | Repeated transient faults spent the attempt budget. |

Duplicate and reordered events are compared per stream: the newest dispatched
delivery for the same repository, ref and event class (ref updates and pull
requests are separate streams even when they share a base branch). An
identical transition is a duplicate; a transition whose new revision is the
newest one's starting point is superseded; anything else — including a forced
rewind to an earlier commit — is a distinct transition and runs.

Every dispatched run records immutable provenance (`run_provenance`, migration
19): the trigger kind, the delivery and provider, the ref transition, the
pull-request head/base/merge revisions and number, the pipeline path and the
exact revision the pipeline was read at, and the compiled pipeline digest. The
worker's expression context is filled from it, so `event.name`, `event.ref`,
`event.key`, `event.base_ref` and `event.pr_number` are real values rather
than unresolved fields (see the [pipeline schema](pipeline-schema.md)).

Settled rows are terminal — the store's trigger refuses reopening one — and
each settlement is logged as `intake_settled` with its delivery and outcome,
and a failed batch as `intake_failed`.

Admission is bounded: at most 1024 open deliveries per repository, after which
a new event is `429 rate_limited` (a duplicate is still acknowledged).
Retention is the operator's: `admin intake list --repo rep_… [--state …]`
shows the newest deliveries, and `admin intake purge --older-than 7d` deletes
settled rows that produced nothing, in bounded batches: never an open one, and
never one a run's provenance depends on.

## Configuration

| File | Purpose |
|---|---|
| `<data_dir>/github-webhook.json` | `{"secret": "…"}` (16–256 printable ASCII), owner-only. Enables the GitHub route. |
| `<data_dir>/source-destinations.json` | the deployment's approved authorities ([sources](sources.md)); intake refuses a repository whose binding is outside it by construction |
| `<data_dir>/master.key` | seals source credentials ([sources](sources.md)); intake tokens are digests and need no key |
| `<data_dir>/intake-work/` | per-delivery scratch repositories for phase two; discarded and recreated on start |

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
- `crates/sentinel-intake/tests/flow.rs`: both ingest paths over a real store,
  including signature/tamper refusals, pull-request terms, and lane resolution
  on a wake and on the idle tick.
- `crates/sentinel-api/tests/api.rs`: the routes over loopback — unscoped
  secrets, size limits, dedup, conflicts, ping, unbound and unsupported
  events, and pull-request actions.
- `crates/sentinel-intake/tests/relay.rs` (Linux, needs `git`, `sh`, `curl`): a
  real push through the example hook — delivery, spooling across a dead
  controller, stable IDs through `--flush`, permanent refusals under `failed/`,
  a full spool, and an unencodable ref refused without a spool write.
- `crates/sentinel/tests/intake_e2e.rs` (Linux, `server`): the real binaries —
  the server loads its webhook secret and destinations, accepts and
  deduplicates a ref update, validates the binding, resolves the pipeline from
  a repository served on loopback HTTPS, creates a run, logs
  `intake_settled` in order, and the CLI lists the durable record with its run,
  keeps it under retention while purging history that produced nothing.