// Y10: the failures this process is meant to survive without touching anything else — a provider
// that never answers, a deadline that has already passed, and a delegation the controller has
// revoked. Each one ends one request as `unavailable` with a reason, and the loop goes on.
//
// The provider is the recording fake these tests share, never a real host: what is asserted is the
// request's own settlement and whether the provider was contacted at all.

import assert from "node:assert/strict";
import test from "node:test";
import { Effect, Redacted } from "effect";
import * as HttpClient from "effect/http/HttpClient";

import { Controller } from "../src/controller.ts";
import { serve } from "../src/service.ts";
import { analysis, chatCompletion, model, recording, reserved } from "./fake.mjs";

const BUNDLE = JSON.stringify({ schema: "sentinel.ai-context/1", attempt: "att_1" });

/** One durable row, with the deadline the controller gave it. */
const row = (id, deadlineMs) => ({
  id,
  attempt: "att_1",
  provider: "openrouter",
  data_policy: "zero_retention",
  origin: "member",
  state: "queued",
  outcome: null,
  reused: false,
  created_ms: 1_700_000_000_000,
  deadline_ms: deadlineMs,
});

const config = {
  controller: "http://controller.internal:8080",
  grant: Redacted.make("service-grant"),
  models: { openrouter: model("fake/model") },
  endpoints: {
    local: { url: "http://127.0.0.1:11434/v1", key: null },
    openrouter: "sk-or-fake",
    anthropic: null,
    openai: null,
  },
  pollMs: 1_000,
};

/**
 * A controller over a queue of requests, recording every reservation and settlement. `evidence`
 * answers the read of a claimed request's bundle, which is where a revocation is seen.
 */
const queued = (requests, evidence = () => Effect.succeed(BUNDLE)) => {
  const settled = [];
  const reservations = [];
  const queue = [...requests];
  return {
    settled,
    reservations,
    impl: {
      next: Effect.sync(() => queue.shift() ?? null),
      claim: () =>
        Effect.succeed({
          request: queue[0] ?? requests[requests.length - 1],
          evidence: "/api/v1/attempts/att_1/ai-context",
          token: { access: "delegated", expires_ms: 0, scopes: ["runs:read"] },
        }),
      evidence,
      reserve: (id, held) =>
        Effect.sync(() => {
          reservations.push({ id, held });
          return reserved();
        }),
      settle: (id, outcome, settledAnalysis, reason, usage) =>
        Effect.sync(() => {
          settled.push({ id, outcome, analysis: settledAnalysis, reason, usage });
        }),
    },
  };
};

/** Runs one poll against a provider client the test supplies. */
const poll = async (memory, client) =>
  Effect.runPromise(
    serve(config).pipe(
      Effect.provideService(Controller, memory.impl),
      Effect.provideService(HttpClient.HttpClient, client),
    ),
  );

test("a provider that never answers is ended by the request's deadline, not by the process", async () => {
  const hanging = HttpClient.make(() => Effect.never);
  const memory = queued([row("air_1", Date.now() + 120)]);
  const started = Date.now();
  const served = await poll(memory, hanging);
  assert.equal(served.served, true);
  assert.equal(served.outcome, "unavailable");
  assert.equal(served.reason, "provider: the request deadline passed before the provider answered");
  assert.ok(Date.now() - started < 5_000, "the poll returned at the deadline");
  assert.deepEqual(
    memory.settled.map((entry) => [entry.outcome, entry.reason, entry.analysis]),
    [["unavailable", served.reason, null]],
    "the request was settled with the reason, and nothing partial was stored",
  );
});

test("a deadline that has already passed never contacts the provider", async () => {
  const fake = recording(() => ({ body: chatCompletion("a provider that must not be asked") }));
  const memory = queued([row("air_1", Date.now() - 1)]);
  const served = await poll(memory, fake.client);
  assert.equal(served.outcome, "unavailable");
  assert.equal(served.reason, "provider: the request deadline passed before the provider was asked");
  assert.deepEqual(fake.calls, [], "no provider request is made with no time left");
  // The maximum was held before the call, and the settlement is what releases it.
  assert.equal(memory.reservations.length, 1, "the request stated what it would cost");
  assert.equal(memory.settled[0].usage, null, "nothing is charged for a call that never happened");
});

test("a revoked delegation ends the request unavailable and holds nothing", async () => {
  const fake = recording(() => ({ body: chatCompletion("a provider that must not be asked") }));
  const memory = queued([row("air_1", Date.now() + 600_000)], () =>
    Effect.fail({ _tag: "ControllerError", reason: "the controller answered 401" }),
  );
  const served = await poll(memory, fake.client);
  assert.equal(served.outcome, "unavailable");
  assert.equal(served.reason, "delegation: the controller answered 401");
  assert.deepEqual(fake.calls, [], "a request with no evidence reaches no provider");
  assert.deepEqual(memory.reservations, [], "a refused read reserves nothing");
  assert.deepEqual(
    memory.settled.map((entry) => entry.outcome),
    ["unavailable"],
  );
});

test("a timed-out provider does not stop the loop serving the next request", async () => {
  const hanging = HttpClient.make(() => Effect.never);
  const memory = queued([
    row("air_1", Date.now() + 80),
    row("air_2", Date.now() + 600_000),
  ]);
  await poll(memory, hanging);
  const answer = recording(() => ({
    body: chatCompletion(JSON.stringify(analysis("the second request's answer"))),
  }));
  const again = await poll(memory, answer.client);
  assert.deepEqual(
    memory.settled.map((entry) => [entry.id, entry.outcome]),
    [
      ["air_1", "unavailable"],
      ["air_2", "completed"],
    ],
  );
  assert.equal(again.outcome, "completed");
  assert.equal(answer.calls.length, 1, "the provider was called once, for the second request");
});
