// The provider-policy gate, against a fake provider: a recording `HttpClient` is the only client
// in the context, so every request the process made is a call the fake saw, and a request it did
// not see was never sent anywhere.
//
// The tenant-side half of the policy — `local_only` may use nothing but the operator's own
// endpoint — is proved the strong way: a `local_only` request naming a hosted provider produces
// zero HTTP calls, and a `local_only` request naming the local provider produces exactly one,
// to loopback.

import assert from "node:assert/strict";
import test from "node:test";
import { Effect, Layer, Redacted } from "effect";
import * as HttpClient from "effect/http/HttpClient";

import { ConfigError, load } from "../src/config.ts";
import { Controller } from "../src/controller.ts";
import { admit } from "../src/policy.ts";
import { modelLayer } from "../src/providers.ts";
import { serve } from "../src/service.ts";
import { chatCompletion, recording } from "./fake.mjs";

const BUNDLE = JSON.stringify({
  schema: "sentinel.ai-context/1",
  attempt: "att_00000000-0000-4000-8000-000000000001",
  failed_step: { index: 1, id: "unit", outcome: "failed", exit_code: 1 },
  log: { frames: [{ id: "log-7", sequence: 7, step: 1, text: "assertion failed: left != right" }] },
});

const row = (overrides) => ({
  id: "air_00000000-0000-4000-8000-000000000002",
  attempt: "att_00000000-0000-4000-8000-000000000001",
  provider: "openrouter",
  data_policy: "local_only",
  state: "queued",
  outcome: null,
  created_ms: 1_700_000_000_000,
  deadline_ms: 1_700_000_900_000,
  ...overrides,
});

const config = (overrides = {}) => ({
  controller: "http://controller.internal:8080",
  grant: Redacted.make("service-grant"),
  models: { local: "fake-local", openrouter: "fake/model", anthropic: "fake-anthropic", openai: "fake-openai" },
  endpoints: {
    local: { url: "http://127.0.0.1:11434/v1", key: null },
    openrouter: "sk-or-fake",
    anthropic: "sk-ant-fake",
    openai: "sk-openai-fake",
  },
  pollMs: 1_000,
  ...overrides,
});

/** An in-memory controller holding one request, recording what the service did to it. */
const controller = (request) => {
  const settled = [];
  return {
    settled,
    impl: {
      next: Effect.succeed(request),
      claim: (id) =>
        Effect.succeed({
          request,
          evidence: `/api/v1/attempts/${request.attempt}/ai-context`,
          token: {
            access: "delegated-grant",
            expires_ms: request.deadline_ms,
            scopes: ["runs:read", "logs:read"],
          },
        }),
      evidence: () => Effect.succeed(BUNDLE),
      settle: (id, outcome, text, reason) =>
        Effect.sync(() => {
          settled.push({ id, outcome, text, reason });
        }),
    },
  };
};

/** Serves one request against the fake provider, returning what happened and every call made. */
const run = async (configuration, request, answer = () => ({ body: chatCompletion("the test failed") })) => {
  const fake = recording(answer);
  const memory = controller(request);
  const served = await Effect.runPromise(
    serve(configuration).pipe(
      Effect.provideService(Controller, memory.impl),
      Effect.provideService(HttpClient.HttpClient, fake.client),
    ),
  );
  return { served, calls: fake.calls, settled: memory.settled };
};

const hosts = (calls) => [...new Set(calls.map((c) => c.host))].sort();

test("a local_only request naming a hosted provider reaches no host at all", async () => {
  for (const provider of ["openrouter", "anthropic", "openai"]) {
    const { served, calls, settled } = await run(config(), row({ provider }));
    assert.deepEqual(calls, [], provider);
    assert.equal(served.outcome, "unavailable");
    assert.match(served.reason, /^policy:/);
    assert.equal(settled.length, 1);
    assert.equal(settled[0].outcome, "unavailable");
    assert.equal(settled[0].text, null);
  }
});

test("a local_only request naming the local provider reaches loopback and nothing else", async () => {
  const { served, calls } = await run(config(), row({ provider: "local" }));
  assert.deepEqual(hosts(calls), ["127.0.0.1"]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, "/v1/chat/completions");
  assert.equal(served.outcome, "completed");
  const body = JSON.parse(calls[0].body);
  assert.match(JSON.stringify(body.messages), /assertion failed: left != right/);
  assert.equal(body.stream, undefined);
});

test("a zero_retention request to OpenRouter carries zdr and a deny of data collection", async () => {
  const { served, calls } = await run(
    config(),
    row({ provider: "openrouter", data_policy: "zero_retention" }),
  );
  assert.deepEqual(hosts(calls), ["openrouter.ai"]);
  const body = JSON.parse(calls[0].body);
  assert.equal(body.provider.zdr, true);
  assert.equal(body.provider.data_collection, "deny");
  assert.match(calls[0].authorization, /^Bearer sk-or-fake$/);
  assert.equal(served.outcome, "completed");
});

test("OpenRouter asks for zero retention whatever the tenant's data policy says", async () => {
  for (const policy of ["provider_terms", "zero_retention"]) {
    const { calls } = await run(config(), row({ provider: "openrouter", data_policy: policy }));
    const body = JSON.parse(calls[0].body);
    assert.equal(body.provider.zdr, true, policy);
  }
  const { calls } = await run(
    config(),
    row({ provider: "openrouter", data_policy: "provider_terms" }),
  );
  assert.equal(JSON.parse(calls[0].body).provider.data_collection, null);
});

test("a provider the deployment configured no model for is refused before any client exists", async () => {
  const { served, calls } = await run(config({ models: {} }), row({ provider: "local" }));
  assert.deepEqual(calls, []);
  assert.match(served.reason, /^config:/);
});

test("a local endpoint outside the operator's network is refused, not called", async () => {
  const refused = load({
    SENTINEL_AI_CONTROLLER: "http://controller.internal:8080",
    SENTINEL_AI_TOKEN: "service-grant",
    SENTINEL_AI_LOCAL_URL: "http://203.0.113.9:11434/v1",
    SENTINEL_AI_MODEL_LOCAL: "fake-local",
  });
  assert.ok(refused instanceof ConfigError);
  assert.match(refused.reason, /SENTINEL_AI_LOCAL_URL/);

  // And the layer refuses again, so a caller that skipped the configuration check cannot build a
  // public client for a tenant whose policy is loopback-only.
  const failed = await Effect.runPromise(
    Effect.scoped(
      Effect.flip(
        Effect.provide(
          Layer.build(
            modelLayer(admit("local_only", "local", "fake-local"), {
              local: { url: "http://198.51.100.7:11434/v1", key: null },
              openrouter: null,
              anthropic: null,
              openai: null,
            }),
          ),
          Layer.succeed(HttpClient.HttpClient, recording(() => ({ body: {} })).client),
        ),
      ),
    ),
  );
  assert.equal(failed._tag, "ProviderError");
  assert.match(failed.reason, /not inside the operator's network/);
});

test("a hosted provider with no key configured is refused, not sent anonymously", async () => {
  for (const provider of ["openrouter", "anthropic", "openai"]) {
    const { served, calls } = await run(
      config({ endpoints: { local: { url: "http://127.0.0.1:1/v1", key: null }, openrouter: null, anthropic: null, openai: null } }),
      row({ provider, data_policy: "provider_terms" }),
    );
    assert.deepEqual(calls, [], provider);
    assert.equal(served.outcome, "unavailable");
    assert.match(served.reason, /^provider: no .* key is configured/);
  }
});
