# Schedules: durable UTC cron occurrences

A schedule runs a repository's pipeline at a fixed UTC instants, without anyone
dispatching it and without a timer living in a controller's memory. Two things
make that durable: the schedule is a row, and each occurrence is a row keyed by
the instant it names. A controller that restarts, a second controller computing
the same instant, or a clock step across it therefore fires one run, not two —
and an occurrence that did not run is still recorded, with what became of it.

A scheduled run is an ordinary run: the same compiler, the same jobs, the same
Checks aggregate, and a `run_provenance` row whose `trigger` is `schedule`. It
publishes no check that a required aggregate would count, exactly as a manual
run does not ([checks](checks.md)). Two consequences follow from having no
authenticated delivery behind it, and both are deliberate: its cache trust is
`unprotected`, so it reads no `protected` cache scope, and it may receive no
secrets — the same rule a manual dispatch follows
([secrets](secrets.md#who-may-cause-a-delivery)). A pipeline that needs a secret
cannot be driven by a schedule today.

## UTC only, and what that means for local time

A cron expression here is five fields — minute, hour, day-of-month, month,
day-of-week — evaluated in UTC, with no zone, no offset and no local calendar.
No daylight saving exists in UTC, so there is no spring-forward hour whose
occurrences are skipped and no fall-back hour that runs them twice: every
occurrence is one instant, and the same expression names the same instants
forever.

An operator who wants a run at 09:00 in Lisbon therefore states the UTC hour
that corresponds to it and accepts that it does not follow a DST change: during
European summer time `0 8 * * *` is 09:00 local, and in winter the same schedule
is 08:00 local. Sentinel does not guess a zone from the deployment, the
repository or the operator; the expression means UTC, and a schedule that should
shift with local time needs two expressions or an edit at the changeover.

Fields accept `*`, a number, a range `a-b`, a step `*/n` or `a-b/n`, and
comma-separated lists of those. Day-of-week is 0–7 with both 0 and 7 naming
Sunday. A day matches when both day fields match, or — as in Vixie cron — when
either of two *restricted* day fields matches; a starred day field does not
constrain the other. An expression with no occurrence in the next eight years
(`0 0 30 2 *`) is refused when it is stored.

## Declaring one: the pipeline admits, the operator stores

The pipeline says it accepts a scheduled run; the stored row says when one
happens. That split keeps the crons off the pipeline's critical path — a fetch
of `.sentinel.yml` at an arbitrary commit never has to be trusted for the
schedule's timing — and it means a schedule can be added, retargeted or stopped
without a push.

```yaml
on: [push, schedule]
```

`schedule: true` in the mapping form of `on:` declares the same thing
([pipeline schema](pipeline-schema.md#source-policies-on)). A pipeline that does
not state it is not run by a schedule: the occurrence is recorded `failed` with
reason `no_trigger`, and the row's cursor still moves past it. A document that
declares named pipelines runs every one of them that states `on.schedule: true`
from one occurrence — one run each, named by the pipeline, with its own checks
([pipeline schema](pipeline-schema.md#named-pipelines)) — and the occurrence
names the first of them.

The row is configured with `sentinel admin schedule set`, on a stopped or a
running controller, and takes a cron, a ref and an overlap policy:

```
sentinel admin schedule set --actor usr_… --repo repo_… \
    --cron "0 6 * * 1-5" --ref refs/heads/main --overlap skip
```

`--ref` defaults to `refs/heads/main` and must be a ref the source binding
already allows: a schedule can never widen what a repository may fetch. The
cursor starts at the first occurrence strictly after the command runs, so
configuring a schedule never replays the past, and re-configuring one restarts
it from the next occurrence.

| Command | Effect |
|---|---|
| `admin schedule set --repo … --cron … [--ref …] [--overlap skip\|cancel]` | store or replace the schedule; prints the first occurrence (`next_at_ms`) |
| `admin schedule disable --repo …` | stop firing it; the row and its history stay readable |
| `admin schedule show --repo …` | the row: cron, ref, overlap, cursor, last occurrence and last run |
| `admin schedule show --all` | every schedule, oldest cursor first |

## One occurrence is one instant

The occurrence table's key is *(schedule, instant)*, and every instant the
cursor passes gets a row. Two controllers that compute the same due minute
therefore insert one row between them, and only the pass that inserted it —
`state = claimed` — resolves and dispatches a run. A controller that dies
between claiming and recording what became of it leaves the row `claimed`; the
next pass claims it again after `CLAIM_TTL_MS` (120 s), so a restart in the
middle of an occurrence neither loses it nor runs it twice.

The cursor only moves forward (`MAX(next_at_ms, …)`), so a pass that reads an
older cursor — a restart, a stale replica, a clock step backwards — cannot move
it back, and cannot fire an instant that already has a row.

## Overlap: `skip` by default, or `cancel`

An occurrence can come due while the run its schedule created last is still
going. `--overlap` decides what happens, and the default is `skip`:

| Policy | Behavior | Recorded |
|---|---|---|
| `skip` (default) | the occurrence does not run; the live run is untouched | `state = 3`, no run |
| `cancel` | the previous run is cancelled (its ready jobs end `canceled`, running ones are asked to stop) and this occurrence runs | the new occurrence's run |

`skip` is the default because a schedule on a slow pipeline would otherwise
spend the fleet on runs that supersede each other; `cancel` is for a schedule
whose newest occurrence is the one that matters, such as a nightly snapshot.

## Missed occurrences: one run, bounded rows

A controller that was down for an hour comes back to a cursor an hour behind.
It does not fire sixty runs. Each pass fires at most **one** occurrence per
schedule — the newest that is due — and every earlier instant of that gap is
folded into one recorded row: keyed at the gap's first instant,
`state = 4` (`missed`), with `skipped` counting the instants it covers.

The scan is bounded at 4096 instants. Past that the row still records the gap,
its `skipped` count is that floor, and its reason is `gap_over_scan`, so the
record says the number is "at least this many" rather than inventing a total for
a year of downtime. Nothing is silently dropped, and the cursor lands after the
fired occurrence, so the next pass starts from the next real instant.

A missed occurrence that is recorded but not fired is not backfilled later: the
schedule resumes at the next occurrence in the future. An operator who needs the
work that was missed dispatches it by hand.

## The pinned revision

Each occurrence resolves the ref it names at that moment, pins the commit the
ref holds then, and fetches `.sentinel.yml` at that commit. Two occurrences of
one schedule may therefore run different commits, and each run knows its own:
`runs.source_sha`, `run_provenance.pipeline_sha` and the immutable run spec all
name the commit the occurrence resolved, not a later tip.

A ref that has vanished (`ref_missing`), a commit with no pipeline
(`no_pipeline`), a pipeline that does not compile (`pipeline_invalid`), a class
the deployment does not define (`artifact_class_unknown`) or a binding that no
longer allows the ref (`ref_not_allowed`) settles the occurrence `failed` with
that reason in `schedule_occurrences.reason`. Schedules are not retried: the
next occurrence fires on its own, and the failed row is the record of the one
that did not.

## Suspension

A suspended tenant's schedules do not fire. The pass checks the tenant before it
claims anything, records the due occurrence `suspended` (with the gap folded the
same way a missed gap is), and moves the cursor past it. Reactivating the tenant
resumes at the next occurrence; the suspended window is not replayed, and it is
not counted as missed — the reason it did not run is recorded, so an operator
reading the row sees a suspension, not a controller outage
([tenancy](tenancy.md)).

## What the schedule lane is, and is not

The controller runs one schedule lane beside intake and polling. A pass claims
due occurrences in one writer transaction — dedup, overlap, the missed bound and
suspension are all decided there — and then resolves each claimed occurrence
outside any transaction, because reading a repository is network work. Only the
reference tips a schedule names are asked for (`git ls-remote <remote> <ref>`),
never a repository's whole ref listing.

A claim a pass cannot finish because the store was busy, overloaded or
unreachable is left claimed for the reclaim to retry; a store refusal that
would fail the same way every pass (a pipeline the store will not encode, for
instance) settles the occurrence `failed` with reason `store_rejected` rather
than retrying it unseen. Settled occurrence rows are kept 90 days and purged like any other
retained record; the cursor moves forward only, so no dedup key it protects can
be older than the gap in front of it.

## Verification

`crates/sentinel-store/tests/schedules.rs` covers one run per occurrence across a
restart and across two schedulers racing, both overlap policies, an hour of
downtime and a year of downtime with their recorded gaps, a suspended tenant and
its reactivation, the pinned revision on each run, the reclaim of a claim whose
controller died, a refused occurrence's reason and the purge.
`crates/sentinel-intake/tests/schedules.rs` drives the real resolver and the lane:
two occurrences pinning two different commits, the `no_trigger` and `no_pipeline`
records, and a due occurrence dispatched by the lane thread.
`crates/sentinel-pipeline/src/cron.rs` covers the expression parser and its
iteration, including a leap day past three ordinary years and the 2100 gap.
