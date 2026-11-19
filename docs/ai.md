# AI assistance

Sentinel's deterministic diagnostics are the authority on why something failed. AI assistance
is optional advisory text on top of them: a model reads a bounded, redacted evidence bundle
built from logs and diagnostics the controller already stored, and writes a summary that cites
the lines it used. This page states the guarantees that hold whether AI is on or off, the
deployment and tenant policy that decides whether it may run at all, and what each data policy
commits to. What is built today is the policy, its routes and its gate; the process that talks
to a provider is [plan 16.6](../plan.md#166-ai-assistance) and the backlog items after Y01.

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
  served (Y02); `sentinel-ai` holds no secret value, no source credential and no whole log.

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
| `zero_retention` | Only providers that keep neither the prompt nor the answer after the response. OpenRouter is called with `provider.zdr: true` and `data_collection: deny`; a provider that cannot honour it is refused rather than called (Y03). |
| `provider_terms` | The provider's own retention terms, which the operator accepts for this tenant. |

`local_only` is a property of the provider the controller knows, so it is enforced at admission
today. `zero_retention` is a property of the request Y03 sends; until that exists the tenant's
choice is stored and enforced by the gate that refuses everything else.

## Disabling

Turning AI off — for the tenant or for the deployment — takes effect at once: the gate below
reads the policy on every request, so the next request that would have been made is refused, and
no queued request survives a disable. The request queue arrives with Y03, and its rows are
deleted in the same writer transaction that clears the flag, before the controller could dispatch
one. Today there is no queue table and nothing that could fill it, so a disabled tenant provably
has no request in flight or pending; `crates/sentinel-store/tests/ai_policy.rs` asserts that and
is the tripwire that makes Y03 replace it with a test of the deletion.

## The gate

`sentinel_store::ai::admit(conn, tenant, provider)` is the single decision every AI request
passes, and the reason no other code needs to know the policy. It answers the data policy a
request may be made under, or nothing at all — because AI is off for the deployment, off for the
tenant, the provider is outside the allow-list, or the data policy does not allow it. Reading it
costs one statement joining the deployment's row to the tenant's, and it allocates nothing. Any
request path that does not call it is a bug: with no opt-in there is no bundle, no prompt and no
provider call.

## What data it would read

The evidence a request is built from is what Sentinel already stores under
[retention](retention.md): a failed attempt's redacted log segments, its deterministic failure
summary and diagnostics, and the step and test identities the pipeline and reports name. The
bundle is bounded (32 KiB by default, Y02), never the whole log; artifacts, caches, secrets and
source credentials are not part of it. An analysis expires with the attempt's logs, because the
evidence it cites does.

## What is not built yet

Y01 is policy only: no provider client, no evidence bundle, no budget ledger and no analysis
exists in the workspace, and no process contacts a provider. [Backlog Part 22](backlog.md)
carries the rest: Y02 the evidence bundle, Y03 the `sentinel-ai` process and its providers, Y04
budgets and caching, Y05 failure analyses, and later flaky tests, the log-search assistant and the
MCP read-only tools that expose them.
