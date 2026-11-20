// The loop's behaviour: one request per poll, and no failure of a provider, a controller or a
// policy can stop it or leak into the run the request is about.

import assert from "node:assert/strict";
import test from "node:test";
import { Effect, Redacted } from "effect";
import * as HttpClient from "effect/http/HttpClient";

import { Controller } from "../src/controller.ts";
import { serve } from "../src/service.ts";
import { chatCompletion, recording } from "./fake.mjs";

const BUNDLE = JSON.stringify({ schema: "sentinel.ai-context/1", attempt: "att_1" });

const row = {
  id: "air_1",
  attempt: "att_1",
  provider: "openrouter",
  data_policy: "zero_retention",
  state: "queued",
  outcome: null,
  created_ms: 1_700_000_000_000,
  deadline_ms: 1_700_000_900_000,
};

const config = {
  controller: "http://controller.internal:8080",
  grant: Redacted.make("service-grant"),
  models: { openrouter: "fake/model" },
  endpoints: {
    local: { url: "http://127.0.0.1:11434/v1", key: null },
    openrouter: "sk-or-fake",
    anthropic: null,
    openai: null,
  },
  pollMs: 1_000,
};

/** A controller over a queue of requests, recording every settlement. */
const queued = (requests) => {
  const settled = [];
  const queue = [...requests];
  return {
    settled,
    impl: {
      next: Effect.sync(() => queue.shift() ?? null),
      claim: (id) =>
        Effect.succeed({
          request: row,
          evidence: "/api/v1/attempts/att_1/ai-context",
          token: { access: "delegated", expires_ms: row.deadline_ms, scopes: ["runs:read"] },
        }),
      evidence: () => Effect.succeed(BUNDLE),
      settle: (id, outcome, text, reason) =>
        Effect.sync(() => {
          settled.push({ id, outcome, text, reason });
        }),
    },
  };
};

const run = async (requests, answer) => {
  const fake = recording(answer);
  const memory = queued(requests);
  const served = await Effect.runPromise(
    serve(config).pipe(
      Effect.provideService(Controller, memory.impl),
      Effect.provideService(HttpClient.HttpClient, fake.client),
    ),
  );
  return { served, calls: fake.calls, settled: memory.settled };
};

test("an empty queue is a poll that served nothing", async () => {
  const { served, calls } = await run([], () => ({ body: chatCompletion("unused") }));
  assert.deepEqual(served, { served: false });
  assert.deepEqual(calls, []);
});

test("a served request is settled with the model's answer", async () => {
  const { served, settled } = await run([row], () => ({ body: chatCompletion("  the lint step failed  ") }));
  assert.equal(served.outcome, "completed");
  assert.deepEqual(settled, [
    { id: "air_1", outcome: "completed", text: "the lint step failed", reason: null },
  ]);
});

test("a provider that fails ends the request as unavailable, never as an answer", async () => {
  const { served, settled } = await run([row], () => ({ status: 503, body: { error: "overloaded" } }));
  assert.equal(served.outcome, "unavailable");
  assert.match(settled[0].reason, /^provider: /);
  assert.equal(settled[0].text, null);
});

test("a provider that answers with nothing is a failure, not an empty analysis", async () => {
  const { served, settled } = await run([row], () => ({ body: chatCompletion("   ") }));
  assert.equal(served.outcome, "unavailable");
  assert.match(settled[0].reason, /^provider: .*answered with no text/);
});

test("a request that fails does not stop the loop: the next poll serves the next request", async () => {
  const answers = [
    () => ({ status: 500, body: {} }),
    () => ({ body: chatCompletion("the second request's answer") }),
  ];
  let poll = 0;
  const fake = recording(() => answers[Math.min(poll++, answers.length - 1)]());
  const memory = queued([row, { ...row, id: "air_2" }]);
  const program = serve(config).pipe(
    Effect.andThen(serve(config)),
    Effect.provideService(Controller, memory.impl),
    Effect.provideService(HttpClient.HttpClient, fake.client),
  );
  const outcomes = await Effect.runPromise(program);
  assert.equal(outcomes.served, true);
  assert.deepEqual(
    memory.settled.map((entry) => [entry.id, entry.outcome]),
    [
      ["air_1", "unavailable"],
      ["air_2", "completed"],
    ],
  );
});

test("a controller that will not take the settlement still leaves the request to its deadline", async () => {
  const fake = recording(() => ({ body: chatCompletion("an answer") }));
  const memory = queued([row]);
  const refused = {
    ...memory.impl,
    settle: () => Effect.fail({ _tag: "ControllerError", reason: "the controller answered 409" }),
  };
  const served = await Effect.runPromise(
    serve(config).pipe(
      Effect.provideService(Controller, refused),
      Effect.provideService(HttpClient.HttpClient, fake.client),
    ),
  );
  assert.equal(served.outcome, "completed");
});
