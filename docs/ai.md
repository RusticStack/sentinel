# AI assistance

Sentinel's deterministic diagnostics are the authority on why something failed. AI assistance
is optional advisory text on top of them: a model reads a bounded, redacted evidence bundle
built from logs and diagnostics the controller already stored, and writes a summary that cites
the lines it used. This page states the guarantees that hold whether AI is on or off, the
deployment and tenant policy that decides whether it may run at all, what the bundle holds, and
what each data policy commits to. What is built today is the policy, its routes, its gate, the
evidence bundle the controller serves, and the separate process that talks to a provider,
`sentinel-ai`, with the durable requests it consumes and the request-scoped credential it reads
evidence with. Budgets (Y04), the analyses themselves (Y05) and everything after are
[plan 16.6](../plan.md#166-ai-assistance) and the backlog items after Y03.

## The guarantees

- **Advisory only.** Nothing an AI feature produces is evidence. Analyses are labelled
  inference, carry citations to the evidence IDs they used, and a citation that does not exist
  is dropped (Y05). The deterministic failure summary, the logs and the diagnostics stay the
  account of what happened.
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
{ "enabled": true, "data_policy": "zero_retention" }
```

The route needs the tenant's `admin` role and a live step-up, and is refused while the
deployment allows no provider. `GET /api/v1/tenants/{slug}/ai` answers the tenant's own choice,
its data policy (`null` until it first opts in) and the providers it may use right now — empty
while either side is off — without a step-up. Every change is audited as
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
4. `POST /ai/requests/{id}/complete` settles the row exactly once, with the answer or the reason
   there is none, and revokes the delegation in the same write. A settled request's delegation no
   longer authenticates; a request past its deadline has none left either.

The row moves `queued` → `claimed` → `settled` and never back. `GET /api/v1/ai/requests/{id}`
answers a member who can read its repository, so the answer the process stored is where Y05 reads
it from, and `crates/sentinel-api/tests/ai_requests.rs` proves the two halves the row's gate names:
a delegation cannot read past the requester, and a `local_only` request reaches no public host.

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
provider call.

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

## What is not built yet

No budget ledger and no analysis exists: `sentinel-ai` settles a request with the model's answer as
plain text, which Y04 replaces with a reserved-and-settled budget and Y05 with an answer decoded
against a schema and cited to the evidence it used. The skeleton has no prompt registry, no
analysis cache and no evaluation set; those are Y04, Y05 and Y09.
[Backlog Part 22](backlog.md) carries the rest, including the later flaky tests, the log-search
assistant and the MCP read-only tools that expose them.

Verification of this package is local: `pnpm typecheck` and
`cd ai && node --import ./test/ts-register.mjs --test test/*.test.mjs`, both of which contact no
provider — the provider tests run against a recording fake HTTP client, and the controller tests
run over the API in `crates/sentinel-api/tests/ai_requests.rs`.
