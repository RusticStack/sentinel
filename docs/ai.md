# AI assistance

Sentinel's deterministic diagnostics are the authority on why something failed. AI assistance
is optional advisory text on top of them: a model reads a bounded, redacted evidence bundle
built from logs and diagnostics the controller already stored, and writes a summary that cites
the lines it used. This page states the guarantees that hold whether AI is on or off, the
deployment and tenant policy that decides whether it may run at all, what the bundle holds, and
what each data policy commits to, and what one tenant's month may cost. What is built today is the
policy, its routes, its gate, the evidence bundle the controller serves, the separate process that
talks to a provider, `sentinel-ai`, with the durable requests it consumes and the request-scoped
credential it reads evidence with, the budget ledger every request reserves against before it goes
anywhere, the analysis cache a repeated question is answered from, and the analyses themselves: a
model's answer decoded against a versioned schema, every claim cited to evidence the controller
resolves, shown as inference under the deterministic summary, expiring with the logs it cites; and
the log-search assistant, where a question becomes a bounded plan of those same reads and an answer
that cites no real line is refused. What follows them — flaky-test summaries, migration
suggestions — is [plan 16.6](../plan.md#166-ai-assistance) and the backlog items after Y07.

## The guarantees

- **Advisory only.** Nothing an AI feature produces is evidence. An analysis is labelled
  inference, carries citations to the evidence IDs it used, and a citation that does not resolve
  is dropped before anyone sees it — an answer whose every citation was dropped is not shown at
  all ([below](#failure-analysis)). The deterministic failure summary, the logs and the
  diagnostics stay the account of what happened, and sit above the analysis wherever it appears.
- **Never on a check's path.** No run, job, attempt, dispatch, log acknowledgement, check
  publication or GitHub delivery waits on a model. A request is a durable row with its own
  deadline, processed asynchronously; a timeout, a provider error or a budget refusal ends it
  as `unavailable`, and the run is untouched.
- **A conclusion never changes.** AI cannot change a job's state, a failure class, a run's
  outcome, or a single GitHub check's conclusion. The checks Sentinel publishes are computed
  from job outcomes alone, and no AI output is read on that path.
- **Isolation when AI is off or failing.** With AI off — the default — Sentinel behaves exactly
  as it did before this feature existed: no request exists, no route that could make one is
  served, and no process contacts a provider. With AI on and its provider failing, the
  isolation ensures a run's timing is what [the B03 budgets](latency-budgets.md) say.
- **No credential reaches a provider.** Sentinel never forwards a Sentinel token, an OAuth
  grant, an installation credential or a job secret to a model provider. The evidence bundle is
  built by the controller from already-redacted logs and diagnostics, re-applying the attempt's
  registered secret values and the token, PEM, cloud-key and JWT scanners before anything is
  served ([below](#the-evidence-bundle)); `sentinel-ai` holds no secret value, no source
  credential and no whole log.

## Deployment policy

AI is **off in a fresh deployment and in an upgraded one**: the migration that adds the policy
inserts nothing, and a deployment with no policy row is off. A platform administrator turns it
on, and names the providers it may use:

```json
PUT /api/v1/admin/ai
{ "enabled": true, "providers": ["local", "openrouter"] }
```

The route needs `platform:admin` and a live step-up, like every other deployment policy
([step-up](step-up.md)); `GET /api/v1/admin/ai` reads it back without a step-up. The allow-list
is a set of the four providers [plan 16.6](../plan.md#166-ai-assistance) names — `local` (an
OpenAI-compatible endpoint on loopback or a private network), `openrouter` (the default hosted
provider), `anthropic` and `openai` — and any other name is refused with the offending name in
`details.provider`. Enabling AI with an empty allow-list is refused: it would allow nothing.

A provider outside the allow-list is never used, whatever a tenant asks for. Withdrawing a
provider takes effect at the next request: the policy is read per request and never cached.

## Tenant policy

A tenant administrator opts one tenant in, under a data policy:

```json
PUT /api/v1/tenants/{slug}/ai
{ "enabled": true, "data_policy": "zero_retention", "auto_analysis": false,
  "budgets": { "monthly_tokens": 2000000, "concurrency": 2 } }
```

`auto_analysis` states whether a failed job gets an analysis nobody asked for
([below](#automatic-analysis)); it is off in a fresh deployment and in an upgraded one, and a field
left out keeps what the tenant had, so changing a data policy never turns it on or off.

The route needs the tenant's `admin` role and a live step-up, and is refused while the
deployment allows no provider. `GET /api/v1/tenants/{slug}/ai` answers the tenant's own choice,
its data policy (`null` until it first opts in), its budget and the providers it may use right
now — empty while either side is off — without a step-up. What the budget fields mean, and what a
request does when it does not fit them, is [below](#budgets). Every change is audited as
`ai-policy-changed` (deployment) or `tenant-ai-policy-changed` (tenant) in
`GET /api/v1/admin/audit`.

| Data policy | What it commits to |
|---|---|
| `local_only` | Only an allow-listed endpoint inside the operator's own network. The controller refuses a hosted provider outright, so a request cannot leave the host. |
| `zero_retention` | Only providers that keep neither the prompt nor the answer after the response. OpenRouter is called with `provider.zdr: true` always and `data_collection: deny` under this policy; a provider that cannot honour it is refused rather than called ([below](#the-process-and-its-providers)). |
| `provider_terms` | The provider's own retention terms, which the operator accepts for this tenant. |

`local_only` is a property of the provider the controller knows, so it is enforced at admission.
`zero_retention` is a property of the request `sentinel-ai` sends, so it is enforced there as well
as here: OpenRouter always carries `provider.zdr: true`, `data_collection: deny` is added under
this policy, and the two direct APIs — which have no per-request retention switch Sentinel could
enforce — are refused for it rather than trusted.

## The process and its providers

`sentinel-ai` is a separate optional Node process in the repository's pnpm workspace (`ai/`, beside
`web/`), written against Effect 4 with exact pins — `effect` and its four AI provider packages at
the same version, because `effect/ai` is tagged `@stability unstable` and a range would let a
minor release change it under a deployment. It is not part of the controller and it never holds a
sentinel secret other than the two credentials below.

**One interface.** Effect's `LanguageModel` is named in exactly one module
(`ai/src/assistant.ts`). Everything else talks to Sentinel's `Assistant`, which asks one question
of one evidence bundle and answers with text and the usage the provider reported — an unreported
count is `null`, never zero. An upstream change to the AI modules therefore moves that one file.

| Provider | Endpoint | What a request carries |
|---|---|---|
| `local` | an OpenAI-compatible endpoint: Ollama, vLLM or a LiteLLM gateway | nothing beyond the prompt; the endpoint is the operator's own, and it is refused at startup unless it stays inside their network (loopback, a private address, or a single-label name only their resolver knows) |
| `openrouter` | `https://openrouter.ai/api/v1` | `provider.zdr: true` always, and `provider.data_collection: deny` under `zero_retention`. Both are layer defaults, so no request path can leave them out |
| `anthropic` | `https://api.anthropic.com` | the bearer key; no retention switch exists to send |
| `openai` | `https://api.openai.com` | the bearer key; no retention switch exists to send |

Only `local` has a configurable address, which is what makes the two rules structural rather than
checked before use: a `local_only` tenant is never given a hosted provider
(`policy.allows` refuses it), and a hosted provider has no configurable host to be pointed at. The
provider-policy tests run the whole path against a recording fake client, and their assertion is
about every request the process made: for a `local_only` request naming a hosted provider, there
are none at all.

```sh
SENTINEL_AI_CONTROLLER=http://127.0.0.1:8080   # the controller's API base
SENTINEL_AI_TOKEN=sntl_…                      # the ai:context grant, shown once when issued
SENTINEL_AI_MODEL_OPENROUTER=…                # one model per provider the deployment allows;
SENTINEL_AI_MODEL_LOCAL=…                     # a provider with no model is refused, not guessed at
SENTINEL_AI_BUDGET_OPENROUTER=4096:150000:600000  # <output cap>:<input micros per Mtok>:
SENTINEL_AI_BUDGET_LOCAL=2048:0:0             # <output micros per Mtok>; a model with no
                                              # budget is refused, not reserved at nothing
SENTINEL_AI_LOCAL_URL=http://127.0.0.1:11434/v1
SENTINEL_AI_LOCAL_KEY=…                       # vLLM and LiteLLM need one; Ollama does not
SENTINEL_AI_OPENROUTER_KEY=…
SENTINEL_AI_POLL_MS=2000                      # at least 100; a request is claimed per poll
```

A configuration it cannot use stops the process before the first poll and names the variable, never
its value.

## Requests and their delegations

A member asks, the controller stores a row, and `sentinel-ai` consumes it through the API. Nothing
in this path waits: no run, job, attempt, dispatch, log acknowledgement, check or GitHub delivery
is on it.

1. `POST /api/v1/tenants/{slug}/ai/requests` writes one durable row — the attempt, the provider,
   the data policy it was admitted under, and its deadline, ten minutes out. A tenant whose policy
   cannot use that provider gets the same `403` as a tenant with AI off, so a row that would have
   reached a host the policy forbids is never written.
2. The process polls `GET /api/v1/ai/requests`, oldest first. That call is also the sweep: a
   request past its deadline is settled `unavailable` there, so nothing stays pending when a
   provider is down, a tenant is disabled or the process is killed.
3. `POST /ai/requests/{id}/claim` leases the row and mints its **delegation**: an `sntl_`
   credential for the requester's own identity, capped to the read-only scopes, bound to that
   request and its attempt, expiring after ten minutes or the row's deadline, whichever is first.
   It is shown once, to the process, and it is what reads the evidence bundle — so the credential
   that sees a bundle can read nothing the requester could not read, and it reads no other
   attempt's bundle even inside a repository the requester can read.
4. `POST /ai/requests/{id}/reserve` is the pre-call decision ([below](#budgets)): it holds the
   request's maximum against its tenant's month, answers from an analysis the ledger already paid
   for, or refuses — and a refusal settles the row in that same write, so nothing waits.
5. `POST /ai/requests/{id}/complete` settles the row exactly once, with the answer or the reason
   there is none and what the provider reported, and revokes the delegation in the same write. A
   settled request's delegation no longer authenticates; a request past its deadline has none left
   either. A second settlement is `409`, and a settlement for a row that is gone — a disable
   deleted the tenant's queue — is `not_found`, so a process that was working when either happened
   learns which it was and neither leaves a half-settled row behind.

The row moves `queued` → `claimed` → `settled` and never back. `GET /api/v1/ai/requests/{id}`
answers a member who can read its repository, so the answer the process stored is where Y05 reads
it from, and `crates/sentinel-api/tests/ai_requests.rs` proves the two halves the row's gate names:
a delegation cannot read past the requester, and a `local_only` request reaches no public host.

**The provider call is bounded by the request's own deadline.** `sentinel-ai` gives the model the
time the row has left and no more, and a request whose deadline has already passed is never sent to
a provider at all. A provider that accepts the connection and never answers therefore ends one
request `unavailable` with `provider: the request deadline passed before the provider answered`,
rather than holding the poll: the loop that was waiting is free to take the next request, which is
the difference between losing one request and losing the tenant's whole queue for as long as the
provider misbehaves. `ai/test/isolation.test.mjs` proves both halves with a fake client that never
completes.

## Budgets

A tenant administrator states what its AI may cost in the same call that opts the tenant in:

```json
PUT /api/v1/tenants/{slug}/ai
{ "enabled": true, "data_policy": "zero_retention",
  "budgets": { "monthly_tokens": 2000000, "monthly_cost_micros": 500000,
               "max_input_tokens": 32000, "max_output_tokens": 4096,
               "max_cost_micros": 100000, "concurrency": 2 } }
```

Every field is optional: the one stated replaces what the tenant had, the ones left out keep it, so
changing a data policy never resets a budget by omission. `GET /tenants/{slug}/ai` reads them back.
The defaults are no monthly ceiling (a monthly field of `0` is no budget at all, as
`tenant_quota_bytes` of `0` is no quota), 32,000 input tokens, 4,096 output tokens and 100,000
micros for one request, and two requests in flight. Cost is in **millionths of the deployment's own
currency**, because Sentinel never guesses a price: `sentinel-ai` holds its model's two rates
(`SENTINEL_AI_BUDGET_<PROVIDER>`), prices the maximum from them, and reports what it actually spent;
the controller stores and compares those numbers and knows nothing about models.

The ledger is two tables. `ai_ledger` is what a tenant was charged, one row per tenant and UTC
calendar month (`YYYYMM`). `ai_reservations` is what a claimed request holds before its provider is
contacted: its maximum tokens and cost, the analysis key it will publish on success, and the request
deadline it expires with. The decision is `charged + held + this request ≤ limit`, read and written in
the same writer transaction, so concurrent requests cannot pass the limit between a check and a hold
— the controller is the only writer and reservations are serialized with it. `GET
/tenants/{slug}/ai/usage` reports the month, the budget, what has been charged, what is held and how
many requests are in flight.

**Refusal is immediate, never queued.** `POST /ai/requests/{id}/reserve` answers one of three
things, and two of them end the request in that same write:

| Answer | What happened |
|---|---|
| `reserved` | The maximum is held until the request's deadline. The provider may be contacted. |
| `reused` | The tenant already has this analysis ([below](#the-analysis-cache)). The request is settled `completed` with it, marked `reused`, and charged nothing. |
| `refused` | Per-request cap, concurrency limit or monthly budget. The request is settled `unavailable` with the reason (`per_request: …`, `concurrency: …`, `budget: …`), and nothing was held. |

Because a refused request is settled by the call that refused it, nothing waits in the queue for its
deadline to notice, and the AI process has no second call to make. The per-request caps and the
concurrency limit are refused on the same path, before any provider exists for the request. The
output cap one request asks for is its model's own (`SENTINEL_AI_BUDGET_*`), which is also the
`max_tokens` the provider is sent, so a deployment whose cap is above a tenant's gets refusals
naming it rather than a cap quietly lowered underneath it: the two numbers have to agree.

**A hold nobody releases expires.** A reservation's `expires_ms` is its request's deadline — ten
minutes — and the sweep that settles an expired request as `unavailable` deletes the reservation in
the same write. A killed AI process therefore holds a tenant's month for at most those ten minutes,
and the next request of the same size is admitted as soon as it has expired.

**Settlement is what the provider reported.** The completion carries the usage the provider stated,
and the ledger is charged per component: an unreported count settles at the reservation's maximum,
because `null` is never zero, and no component settles above what was held, so a call can never
spend past the maximum that was approved before it. A reservation is charged to the month it was
made in, even when it settles after midnight on the last day of one.

## The analysis cache

The same question over the same evidence costs nothing the second time, and a rerun of the same
failure reuses what the earlier run paid for. An analysis is stored under its tenant and three key
parts — the evidence, the prompt and the model — in `ai_analyses`, and `reserve` looks it up before
it looks at any cap, limit or budget, because an answer already paid for costs nothing to serve:

- **The evidence digest** is the exact bundle `sentinel-ai` would send, byte for byte: the same
  attempt asked twice, with the same bundle budget, is one question. A bundle that gained a log
  frame is a different question.
- **The failure fingerprint** is what survives a new attempt: the failure class, the normalized
  failed step, each diagnostic's test identity or code location, and the first line of each
  diagnostic's message with the run's specifics — addresses, durations, numbers — masked. A rerun of
  the same failing test finds the earlier analysis under it.
- **The prompt version and the model** are part of both keys. Changing the instructions or the model
  makes every stored analysis inapplicable rather than subtly wrong.

A served analysis settles the request `completed` with `reused` set and a `by` of `evidence` or
`fingerprint`, and the member's row reports `reused: true`. Only a tenant's own analyses can answer
its requests. An analysis is kept for the shorter of 30 days and the retention of the log it cites
([expiry](#expiry)), and pruned by the sweep that expires requests; a disable deletes a tenant's
analyses with its queue. A reused analysis cites the evidence of the
attempt it was computed from — which is why the row says `reused` rather than the text pretending to
describe this run's log.

## Failure analysis

The analysis is the point of all of it, and it is one document with one shape. `sentinel-ai` asks
the model for `sentinel.ai-analysis/1`: a summary, and up to eight claims, each with one to eight
citations. A citation names the attempt and the bundle's own identifier for what it rests on — a
log frame (`log-<sequence>`) or a diagnostic (`diag-<n>`). The prompt states the schema, the bounds
and the identifiers, and it says the thing that makes the rest of this possible: a claim the evidence
does not support is a claim to leave out.

**Decoded, never repaired.** The model's answer is a JSON document or it is nothing. `sentinel-ai`
decodes it first, so a malformed answer ends the request `unavailable` with the field named instead
of travelling on; the controller decodes it again in `POST /ai/requests/{id}/complete` and refuses
(`invalid_request` with `details.field`) anything that does not match: another schema string, a
missing or unknown field, a blank summary, more claims or citations than the bounds, a claim with no
citation at all, an attempt that is not an attempt, an evidence identifier the bundle could not have
assigned. A refused answer settles nothing — the request keeps its claim and its deadline — and only
a whole document is ever stored. There is no truncation of an answer, because a citation cut off the
end is a claim nobody can check.

**Citations are resolved before the answer is shown.** The stored document is not served as it was
written. For every citation the controller checks, against the evidence it stored: that the attempt
it names is one of the same repository's, that a `log-<sequence>` is still a frame of the page the
evidence bundle is built from, that a `diag-<n>` is one of the diagnostics that page parses into
(failures and errors first, at most 20), and that retention has not removed the log. A citation that
fails any of those is dropped and counted. A claim left with no citation is dropped with it. And an
analysis whose every claim was dropped is **not shown as an analysis at all**: the route answers
`present: false`. A claim nobody can check must not look like a finding.

What a served analysis carries is the resolved form — each citation names the run, the attempt, the
frame sequence and the step, so the interface can open the log at the line it cites — plus
`inference: true`, whether the answer was reused, and `expires_ms`. Nothing else reads it: no run
state, no job state, no failure class and no check conclusion is ever computed from an analysis,
which `crates/sentinel-api/tests/ai_analysis.rs` proves by comparing a run's conclusion, its job's
state and failure class and every published check before and after one is served.

**Inference, under the deterministic summary.** The attempt's failure summary is the account; the
analysis sits below it, labelled as inference, in the run page's failure view
([interface](#where-it-appears)).

### Automatic analysis

A tenant administrator can ask for an analysis of every failed job: `auto_analysis` in the tenant's
AI policy, off by default and off after an upgrade. Sentinel has no advisory job — every job is a
required one, and a failed job's check is what fails its run — so the target is a job that ended
`failed`; a passed, cancelled, skipped or timed-out job gets nothing.

Nothing on the failure path writes that request. The AI process's own poll (`GET /ai/requests`,
which is also the expiry sweep) writes it: a bounded batch per poll, one request per failed attempt
(by a unique index, so a sweep that runs twice writes once), inside a ten-minute window of the
failure — so turning the switch on never turns a tenant's history into a bill. The requester is the
tenant administrator whose decision turned it on, so the delegation minted at claim reads exactly
what they could. The provider is the first the deployment allows that the tenant's data policy
permits, in the providers' own order, so two sweeps over one policy choose alike. From there it is
an ordinary request: reserved against the month, refused if it does not fit, cached like any other.

### Expiry

An analysis expires with the logs it cites, not with a calendar of its own. The cache row's expiry
is the earlier of the cache's 30 days and the attempt log's retention, and an analysis whose log is
already gone is not cached at all (the request still carries its answer, which is not served). At
read time a citation into a log retention removed does not resolve, so the answer stops being shown
the moment its evidence does: nothing outlives what it cites.

## The log-search assistant

A failure analysis answers *why did this fail*. A question answers *what happened*, and a question
is not bound to one attempt: it may need the logs of twenty runs before the answer is anywhere in
one of them. So a question never reaches a log directly. It becomes a **plan** — a bounded list of
reads of what the controller already serves — the controller executes that plan under the
requester's own delegation, and the model sees only the result. `sentinel.ai-plan/1` is the plan:
at most six reads, each either a literal search over the repository's newest runs (a needle of at
most 256 bytes, a window of at most 100 runs, at most 25 matching lines) or one attempt's failure
context ([the bundle](#the-evidence-bundle)).

**One request, two calls, one hold.** A member asks by adding a `question` to their request
(`POST /tenants/{slug}/ai/requests`, 1–512 bytes, which needs `logs:read` as well as the read-only
set). The row's `kind` says which answer is owed: `search` for a question, `analysis` for a
failure. At claim time `sentinel-ai` reserves once for both provider calls — the planner's prompt
and the answer's, priced against the largest result document the plan may return — and that one
maximum is what Y04's ledger holds, so the per-request cap and the month's budget bound the whole
question and not half of it. The planner may use 512 output tokens of the cap and the answer the
rest; a cap that leaves no room for both refuses the request rather than planning one.

**Executed as the requester.** `POST /ai/requests/{id}/plan` takes the plan and runs the reads with
the requester's own authority, re-read at that moment: the request's repository, its tenant's AI
policy, and the reads themselves. A read naming an attempt of another repository, or another
tenant, is refused with the read's index — never skipped, never satisfied from what the request
could read when it was created — and the same write settles the request `unavailable`, so a
refused plan is the end of the question. A plan the controller cannot execute (another schema, an
unknown field, a read past its bounds) and a plan whose reads exceed the 4 MiB of log one plan may
scan or whose results exceed 64 KiB is refused the same way, with the reason on the row. Nothing
is truncated to fit: a silently shortened answer would be a claim nobody can check. Within those
bounds a search read reports whether it saw everything it could (`truncated`, `expired_attempts`,
`missing_logs`), so a model never states that a log held nothing when it held more than the read
looked at.

**What the model sees.** The answer to a plan is one `sentinel.ai-search/1` document: each search
read's matching lines with the attempt, run, job, step, stream and evidence identifier
(`log-<sequence>`) the answer will cite, and each context read's bundle. It is the only thing the
answer's prompt carries — no log, no bundle of the process's own choosing — and the credential
scanners are re-applied to every line, because a line reaches a log through paths no registered
value covers. Nothing outside the request's repository can appear in it, because nothing outside
it was read.

**Every answer links real lines.** The answer is the same `sentinel.ai-analysis/1` document a
failure analysis is, so it is decoded and its citations resolved the same way — one implementation
for both. The difference is where the check happens: a log-search answer is checked when it is
stored. `POST /ai/requests/{id}/complete` resolves every citation against the evidence the
repository still holds, and an answer whose every claim drops — a frame that does not exist, a
diagnostic the bundle does not number, an attempt outside the repository, a log retention removed —
is **not stored**: the request settles `unavailable` with
`citation: no claim cites evidence this repository's logs hold`. The answer is never shown and
never cached, which is stricter than an analysis, whose route drops what no longer resolves and
hides a document that lost every claim.

**Cost and the cache.** A question is cached like an analysis, keyed by the attempt it was asked
about, the question, the prompt version `search-1` and the model, so the same question about the
same request costs nothing the second time and the same question about another repository is a
different question. A reused answer is re-resolved where it is served, so a line retention removed
is not a line a cached answer still links.

What is not built: no interface yet — the run page's analysis panel has no question box, and the
answer is read through `GET /ai/requests/{id}` — and no multi-round planning: one plan, one answer,
which is what makes the bound a number rather than a loop.

## Where it appears

The run page's failure view — the same deterministic summary — gets the analysis underneath it,
fetched from `GET /attempts/{id}/ai-analysis` after the page shows: a short panel labelled *AI
analysis* and *inference*, never above the deterministic summary and never in place of it, with
every citation a link to the log line it names. With AI off, or with no analysis yet, the panel is
not there at all; a request still in flight says so in one line. The browser test drives this view
with a stored analysis and a citation that opens the log at its line, and checks the label and the
order ([web interface](web-ui.md)).

## Disabling

Turning AI off — for the tenant or for the deployment — takes effect at once: the gate below reads
the policy on every request, so the next request that would have been made is refused, and no
queued request survives a disable. The request queue is deleted in the same writer transaction
that clears the flag, and the delegations those rows minted are revoked there too, so a request
being processed at the moment of the disable loses its evidence read and ends `unavailable`.
A policy change that withdraws a provider deletes the queued rows naming it, and leaves a claimed
one to its own deadline. `crates/sentinel-store/tests/ai_policy.rs` proves the deletion and the
revocation, both in the one write.

## The gate

`sentinel_store::ai::admit(conn, tenant, provider)` is the single decision every AI request
passes, and the reason no other code needs to know the policy. It answers the data policy a
request may be made under, or nothing at all — because AI is off for the deployment, off for the
tenant, the provider is outside the allow-list, or the data policy does not allow it. Reading it
costs one statement joining the deployment's row to the tenant's, and it allocates nothing. Any
request path that does not call it is a bug: with no opt-in there is no bundle, no prompt and no
provider call. The second half of the gate is `sentinel_store::ai::reserve`, which no provider call
may skip either: it is the one write that holds a maximum, answers from the cache or refuses, and
its three answers are the only ways a claimed request can leave the queue for a provider.

`sentinel_store::ai::permits(conn, tenant)` is the same reading without a provider named, for the
bundle: it is `admit` for whichever provider the tenant may use, so a tenant that could send
nothing gets no bundle either. It is one statement and no cache, so a disable refuses the next
bundle.

## The evidence bundle

`GET /api/v1/attempts/{id}/ai-context` is what an AI process reads instead of a log
([API](api.md#routes)). It is one JSON document, `sentinel.ai-context/1`, built on request from
what the controller already stored:

- **The deterministic record**: the attempt's terminal summary — the failed step and its exit
  code or signal, every step's outcome and duration, and the job's state and failure class while
  this attempt still owns the job.
- **Diagnostics**: what the attempt's stored log frames parse into as Go test or rustc JSON, with
  the same parsers and the same evidence references the failure context uses
  ([diagnostics](diagnostics.md)). Nothing is opened that a person could not read: no artifact,
  no cache, no secret.
- **The log**: the newest frames of the failed step, in order, each with its sequence so an
  analysis can cite it.

Each part is capped before the bound applies: at most 20 diagnostics, 8 steps (the failed one
first) and 1,024 bytes of a diagnostic's message, the rest counted in `omitted_diagnostics` and
`omitted_steps`. The bound is 32 KiB by default and 1,024–65,536 bytes by `budget`. A bundle that would exceed it
is **truncated, never oversized**, and the truncation is visible in the document: `bounds.bytes`
is the served body's exact length, `bounds.truncated` is set, frames and diagnostics dropped whole
are counted, and a frame that lost bytes carries `cut` with the newest of its text — a failure is
usually explained by what came last, so the oldest bytes go first.

Two redaction passes run over every text field before anything is served:

1. **The attempt's registered values.** The versions its secret delivery recorded using
   (`secret_audit`), unsealed again for this one read, registered in the same
   `sentinel_protocol::redact::Redactor` the worker runs before a byte reaches its spool — one
   implementation, so the bundle redacts the way the log was redacted. Values are matched raw,
   base64-encoded, percent-encoded and JSON-escaped, as at write time.
2. **The credential-shaped scanners** (`sentinel_protocol::patterns`), because a token can reach a
   log through a path no registered value covers: Sentinel `sntl_` credentials and access, refresh,
   code and device tokens; GitHub `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_`
   credentials; PEM private-key blocks, including one cut before its end marker; AWS access key
   IDs, Google API keys and Azure `AccountKey` values; and JWTs.

`redaction` in the document states how many values were registered, how many text fields the
values rewrote, and which patterns fired. A clean bundle reports `pattern_replacements: 0` and no
patterns, and `crates/sentinel-api/tests/ai_context.rs` proves the other case end to end: a
registered canary value, a GitHub token, a PEM block, an AWS key and a JWT in the stored log, and
none of them in the bundle the route serves.

## Who may read a bundle

Only a credential whose scopes list `ai:context`. No permission set implies it
([OAuth](oauth.md#tokens-scopes-and-lifetimes)), so a browser session, an `sntl_` API credential and
the shipped CLI's token can never read a bundle even though they read the log and the failure
context; the grant is issued to the AI service's own account.

The one other credential that may read a bundle is a request's delegation, and only for its own
request's attempt while that request is claimed and before its deadline ([above](#requests-and-their-delegations)).
A delegation is read-only by construction, so it can never widen what a person may see: it *is*
that person, minus every write.

## What data it reads

The evidence a request is built from is what Sentinel already stores under
[retention](retention.md): a failed attempt's redacted log segments, its deterministic failure
summary and diagnostics, and the step and test identities the pipeline and reports name. The
bundle is bounded and never the whole log; artifacts, caches, secrets and source credentials are
not part of it ([above](#the-evidence-bundle)). An analysis expires with the attempt's logs,
because the evidence it cites does.

## Evaluation

The analysis prompt is evaluated on a committed set of seeded failures, `ai/eval/cases/*.json`: two
on each pilot (a failing test and a failing build on GitHub CLI, ripgrep and gson) and the X08
fixture, whose failing line is the first thing in a 100 MiB log and so reaches the bundle only as a
diagnostic, behind a window of noise, prompt-like instructions and a binary frame. A case is the
`sentinel.ai-context/1` bundle of the failed attempt, the identifiers of the line with the actual
error (`error_evidence`: citing any one is a hit) and the canary values the seeded log held and the
bundle must not.

`ai/src/evaluation.ts` serves each case through `serve` as a queued analysis request, with the
controller in memory and every request body to the provider recorded, and scores:

| Score | Meaning | Gate |
|---|---|---|
| `error_line_share` | cases whose analysis cites the actual error line, over all cases; an `unavailable` request cites nothing | may not fall below the baseline |
| `citation_validity` | citations naming the bundle's own attempt and an identifier the bundle holds, over all citations | exactly 1 |
| `canary_leaks` | occurrences in a recorded request body of a case's canary, or of a token prefix, key shape or PEM header | exactly 0 |
| `cost_p95_micros` | nearest-rank p95 of the provider-reported cost of each completed analysis | at most 1.1x the baseline |
| `latency_p95_ms` | nearest-rank p95 of one `serve` call, per completed analysis | at most 1.5x the baseline |

A run is one `sentinel.ai-eval/1` record keyed by provider, model, prompt version and the set's
digest; its baseline is the last record in `ai/eval/results.jsonl` with the same key, so a new
model, a new prompt version or a changed set starts a baseline of its own and is held only to the
two absolute gates. `node src/evaluate.ts <provider> [--write]` in `ai/` runs the set against the
provider the environment configures, prints the record, exits 1 when the gate refuses it and with
`--write` appends a passing record to `results.jsonl`, which is committed with the prompt or model
change it measured. `ai/test/evaluation.test.mjs` checks the set, the scoring and the gate against
the recording fake provider, and that every committed record passes the gate against the one before
it.

Not done, and why Y09 stays open: the cases are written by hand in the shape the controller serves,
not captured from seeded runs on the pilots (Blocked by: the verification hosts), and
`results.jsonl` is empty because no provider has been called (Blocked by: provider credentials for
an evaluation run). The canary score here covers what the AI process sends; that the controller's
bundle never holds a canary is `crates/sentinel-api/tests/ai_context.rs`.

## What is built and what is not

The evaluation set, its scoring and its gate are built ([Evaluation](#evaluation)); its cases are
written in the bundle's shape rather than captured from pilot runs, and no measured record is
committed yet. Two prompts ship, each with its version in every cache key —
`analysis-1` for a failure analysis and `search-1` for the reads a question becomes. The features
after Y10 — flaky-test summaries, migration suggestions, the read-only MCP tools that expose
analyses — are [plan 16.6](../plan.md#166-ai-assistance) and [backlog Part 22](backlog.md).

Verification of this package is local: `pnpm typecheck` and
`cd ai && node --import ./test/ts-register.mjs --test test/*.test.mjs`, both of which contact no
provider — the provider tests run against a recording fake HTTP client, and the controller tests
run over the API in `crates/sentinel-api/tests/ai_requests.rs`, `ai_budget.rs`, `ai_analysis.rs`,
`ai_search.rs` and `ai_isolation.rs`.

The failure drills are the Y10 set: `crates/sentinel-api/tests/ai_isolation.rs` drives a provider
outage, a slow provider, an exhausted budget, a disable mid-processing and a killed process over the
real routes, and compares every deterministic surface of a failing and a passing run with AI on
against the same run with AI off through a real worker session; `ai/test/isolation.test.mjs` drives
the process's half of the slow provider and a delegation the controller has revoked. What each drill
leaves simulated is stated in [resilience](resilience.md#what-is-not-covered): the provider and the
signal that kills the process.

The log-search assistant's gates are `crates/sentinel-api/tests/ai_search.rs`: a question's plan is
executed under the request's delegation and its lines are the ones a citation resolves to, a plan
past its reads, needle, run window, match count or result bytes is refused with its field and the
row settled, a plan naming another repository's attempt is refused and that attempt stays unreadable
to the delegation, and an answer citing nothing that resolves is refused rather than stored;
`ai/test/search.test.mjs` proves the process's half — the plan reaches the controller before any
answer is asked for, the answer's prompt carries the result document and nothing else, an
out-of-bounds plan never leaves the process, and one hold covers both calls. The budget's own
gates are `crates/sentinel-store/tests/ai_budget.rs`: budget and cost are charged from reported
usage, an unreported component settles at its hold, an unsettled reservation expires with its
request and frees the month, 24 concurrent reservations against a budget of eight admit exactly
eight and settle every other request in the write that refused it, per-request caps and the
concurrency limit refuse before anything is held, a fingerprint is reused across reruns and a
different prompt version, model or failure is not, and a disable takes the analyses and the
reservations with the queue. The analysis's own gates are `crates/sentinel-protocol`'s schema tests
(a malformed, partial or unknown-field answer is refused whole, and every bound is enforced),
`ai/test/analysis.test.mjs` for the process's half of the same decode, `ai/test/service.test.mjs`
for a provider answer that is not an analysis ending the request `unavailable` with nothing stored,
`crates/sentinel-store/tests/ai_analysis.rs` (automatic analysis only for a failed job, only when
the tenant turned it on, one request per failure and none for a failure older than the window; an
analysis cached for the shorter of 30 days and its log's retention, and not cached once the log is
gone) and `crates/sentinel-api/tests/ai_analysis.rs` (decoded before it is stored, a citation that
does not resolve dropped, an all-dropped answer not shown, a refusal naming the field and settling
nothing, the run/job/check invariant, expiry with the logs, and the poll that writes the automatic
request). The interface's gate is the browser test over the run page's failure view.
