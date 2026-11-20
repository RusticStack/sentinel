# Shadow runs and parity

A migration is proven by running the same job twice on the same commit: the original on GitHub's
runner, and a non-required copy on Sentinel ([plan 16.5](../plan.md#165-guided-github-actions-migration)).
This page is what that copy is called, what the parity report compares, and what this release can
and cannot show.

## What a pair is

A pair is one GitHub job and its copy, on one commit, named the same way in both modes:

| Mode | The copy | Sentinel's record of it |
|---|---|---|
| Runner mode | a job of the same workflow with a Sentinel label and `name: sentinel / <original>`, so GitHub runs it beside the unchanged original | the `runner_jobs` row its `workflow_job` deliveries wrote |
| Native path | a job of the shadow pipeline, whose per-job check is `sentinel / <job>` | the check it published, and the job's own phase stamps |

The prefix is the one every per-job check already carries (`checks::JOB_PREFIX`), so a copy is
non-required by construction: no branch protection requires a `sentinel / …` check, and the
original's required check keeps its name and its authority. A matrix job's copy is expanded the way
GitHub expands the original, so `build (1.24)` is paired with `sentinel / build (1.24)`.

The pairs are stated, not guessed: a native job is named per matrix cell
(`build-1-24`), which no rule can reverse, and the wizard holds the mapping the preview generated.
Each pair names its commit, its original and its copy. A copy Sentinel holds at one of the report's
commits that no pair names is listed in `unpaired`, so a comparison can never be narrowed to the
pairs that suit it.

## What is compared

Per pair: the conclusion, the test counts and the duration. Both sides are measured facts.

- **Conclusion** is the text GitHub's page states for the original and, for the copy, the conclusion
  Sentinel recorded — the check it published (native) or the delivery that completed the job
  (runner mode). A job that has not concluded states none, and a pair whose sides disagree is a
  `conclusion` mismatch.
- **Test counts** are `total`, `failed` and `skipped`, counted from the report a job produced —
  JUnit XML or Go JSON, read by the pipeline's own parsers ([diagnostics](../crates/sentinel-protocol/src/diagnostics/parse.rs)),
  so a parity count is exactly what Sentinel would count for the same file. A job that stated no
  report is `Unreported`: never zero tests, and never an agreement. Both sides unreported is
  `tests_unreported`, one side unreported is the same finding, and a job that really ran no tests
  states zero and matches another that states zero.
- **Duration** is wall time. For the original it is the page's `started_at`…`completed_at`, which is
  the same span as every other reported figure. For a native copy it is the job's lease…terminal
  phase stamps — preparation, steps and finalization without the queue — and for a runner-mode copy
  the delivery's `started_ms`…`completed_ms`. A copy is a `duration` mismatch when it took more than
  twice the original's time **and** more than a second longer: a second of noise on a two-minute job
  is not the finding a minute on a ten-second one is. The copy's wait for a runner is reported
  separately as `queue_ms`, because it is Sentinel's overhead and not the job's work.
- **Absent is not equal.** A duration, conclusion or report that a side never stated is a mismatch of
  its kind, not a pass: what was not measured was not compared.

## Percentiles

Aggregates are per job name over every pair in the report: `matched`, `mismatched`, and `p50_ms` and
`p95_ms` of each side over the pairs whose two sides both stated a duration. `samples` is that count
and it is the basis of the percentiles — nearest rank over the sorted samples, so `p95` of ten
samples is the tenth and no figure is ever interpolated from data that is not there. A week of pushes
is compared by sending the week's Actions pages; a report that covers few commits says so in its sample
count rather than implying more.

## The route, and what it costs

`POST /tenants/{slug}/repos/{name}/migration/parity` ([API](api.md#routes)) answers the report. It is
a read: it writes nothing, contacts nothing, and every figure it answers with is either what the
caller's Actions pages stated or what Sentinel recorded. The controller holds no Actions client for
this route in this release, so the caller sends what it read — the same shape as the
[migration preview](workflow-analysis.md#the-change-generator), which is sent the workflow files it
read at a pinned commit.

The reads behind it are bounded and keyed, and the query plans are asserted in
[`crates/sentinel-store/tests/parity.rs`](../crates/sentinel-store/tests/parity.rs):

| Read | Statement | Index |
|---|---|---|
| the repository is this tenant's | `REPO_SQL` | `repos` ownership |
| the newest run at one commit | `RUN_AT_SHA_SQL` | `runs_by_sha`, no sort |
| one run's jobs and their phases | `RUN_JOBS_SQL` | `jobs_by_run` |
| one run's per-job checks | `RUN_CHECKS_SQL` | `check_publications_run` |
| one GitHub job as runner mode booked it | `RUNNER_JOB_SQL` | `runner_jobs` primary key |

One report reads at most 64 commits (one probe for the run and one each for its jobs and its checks)
and at most 256 pairs, and probes `runner_jobs` at most once per GitHub job id it compares; the
Actions pages are
decoded with the jobs endpoint's own `per_page` bound of 100 jobs a page, and a job entry the decoder
cannot read is dropped rather than failing the page. No statement in the path scans a table.

## What this release verifies, and what it cannot

The tests are [`crates/sentinel-store/tests/parity.rs`](../crates/sentinel-store/tests/parity.rs),
[`crates/sentinel-api/tests/migration_parity.rs`](../crates/sentinel-api/tests/migration_parity.rs),
the Actions decoder's own cases in [`sentinel-github`](../crates/sentinel-github/src/actions.rs) and
the counting cases in [`sentinel-protocol`](../crates/sentinel-protocol/src/diagnostics/parse.rs).
They cover the gate: a pair that matches and a pair that does not are both reported correctly, with
each difference listed; a job with no test reports says so instead of counting zero tests as a match;
a copy Sentinel never ran and a copy no pair names are both named; the percentiles are computed over
the samples they count; and the reads are indexed.

What they cannot cover, because they need things this host does not have: a real `actions/runner`
job and a real Actions jobs response (the decoder is driven from recorded pages, so its shape is this
release's reading of GitHub's, not GitHub's current answer), a real App installation reading that
page, and the row's own gate — a week of pushes on the three pilot forks compared pair by pair. That
is AR11's and H05's pilot record, and this release states the residual rather than claiming it.
