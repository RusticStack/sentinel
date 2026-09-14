# Event intake: ref updates, webhooks and durable resolution (G02)

Part 05 starts two ways: a person or agent dispatches a pinned pipeline through
the [API](api.md), or a repository tells Sentinel that something changed. This
document is the second path. Intake is deliberately small: authenticate, bound,
store, acknowledge, and let a bounded lane resolve off the request path. No
route starts a container, fetches a pipeline or waits for a run.

Resolution here validates the *source* — the binding and ref are still
executable — and settles the delivery as `ready`. The policy-selected pipeline
fetch, compilation and immutable run creation are G03.

## Two authenticated shapes, one store

| | Generic ref update | GitHub webhook |
|---|---|---|
| Route | `POST /api/v1/intake/{repo}` | `POST /api/v1/hooks/github` |
| Credential | per-repository hook secret (`Authorization: Bearer sentinel_hook_…`) | App webhook secret (HMAC-SHA256 over the raw body in `X-Hub-Signature-256`) |
| Identity | the relay's own stable delivery ID | `X-GitHub-Delivery` |
| Event | one ref transition (always `ref_update`) | `X-GitHub-Event` (`push` today) |
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

A GitHub `push` keeps only the fields intake needs (installation ID,
immutable repository ID, ref, before/after). The delivery is attributed to the
repository of the *bound* App installation — the payload cannot name a tenant,
and an unbound repository is answered `200 {"ignored": "unbound_repository"}`
so GitHub does not retry it. Events this build does not handle yet
(`pull_request`) are acknowledged the same way: `{"ignored":
"unsupported_event"}`.

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
of 64 inside one writer transaction, woken immediately by an accepted delivery
and otherwise by a 250 ms tick; store failures back off from 1 s to 30 s. Each
delivery is revalidated against the binding **as it is now**:

| Outcome | Meaning |
|---|---|
| `ready` | The binding is active, the ref is allowed and the revision is not a deletion. G03 compiles and dispatches from here. |
| `ignored:ref_deleted` | A deletion or an event with no ref: understood, deliberately not a trigger. |
| `failed:binding_revoked` | The binding was revoked (or the tenant suspended) between acceptance and resolution. |
| `failed:ref_not_allowed` | The binding no longer allows this ref. |
| `failed:resolution_attempts` | Repeated transient faults spent the attempt budget; the reason is recorded. |

Settled rows are terminal — the store's trigger refuses reopening one — and
each settlement is logged as `intake_settled` with its delivery and outcome,
and a failed batch as `intake_failed`.

Admission is bounded: at most 1024 pending deliveries per repository, after
which a new event is `429 rate_limited` (a duplicate is still acknowledged).
Retention is the operator's: `admin intake list --repo rep_… [--state …]` shows
the newest deliveries, and `admin intake purge --older-than 7d` deletes settled
rows in bounded batches, never a pending one.

## Configuration

| File | Purpose |
|---|---|
| `<data_dir>/github-webhook.json` | `{"secret": "…"}` (16–256 printable ASCII), owner-only. Enables the GitHub route. |
| `<data_dir>/source-destinations.json` | the deployment's approved authorities ([sources](sources.md)); intake refuses a repository whose binding is outside it by construction |
| `<data_dir>/master.key` | seals source credentials ([sources](sources.md)); intake tokens are digests and need no key |

## Verification

- `crates/sentinel-github` unit tests: raw-body HMAC exactness (a reformatted
  body fails), malformed headers, wrong keys, and bounded push parsing.
- `crates/sentinel-store/tests/intake.rs`: dedup and mismatch, malformed terms,
  the admission bound, digest-only rotatable/revocable secrets, GitHub targets
  through a bound installation only, every resolution outcome, retry backoff
  and attempt exhaustion, retention purging settled rows only, and immutable
  terms through raw SQL.
- `crates/sentinel-intake/tests/flow.rs`: both ingest paths over a real store,
  including signature/tamper refusals and lane resolution on a wake and on the
  idle tick.
- `crates/sentinel-api/tests/api.rs`: the routes over loopback — unscoped
  secrets, size limits, dedup, conflicts, ping, unbound and unsupported
  events.
- `crates/sentinel-intake/tests/relay.rs` (Linux, needs `git`, `sh`, `curl`): a
  real push through the example hook — delivery, spooling across a dead
  controller, stable IDs through `--flush`, permanent refusals under `failed/`,
  a full spool, and an unencodable ref refused without a spool write.
- `crates/sentinel/tests/intake_e2e.rs` (Linux, `server`): the real binaries —
  the server loads its webhook secret, accepts and deduplicates a ref update,
  logs `intake_settled` with the `ready` outcome, and the CLI lists and purges
  the durable record after shutdown.
