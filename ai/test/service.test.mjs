// The loop's behaviour: one request per poll, and no failure of a provider, a controller or a
// policy can stop it or leak into the run the request is about.

import assert from "node:assert/strict";
import test from "node:test";
import { Effect, Redacted } from "effect";
import * as HttpClient from "effect/http/HttpClient";

import { Controller } from "../src/controller.ts";
import { PROMPT_VERSION, serve } from "../src/service.ts";
import { analysis, chatCompletion, model, recording, refused, reserved, reused } from "./fake.mjs";

const BUNDLE = JSON.stringify({ schema: "sentinel.ai-context/1", attempt: "att_1" });

const row = {
  id: "air_1",
  attempt: "att_1",
  provider: "openrouter",
  data_policy: "zero_retention",
  origin: "member",
  state: "queued",
  outcome: null,
  reused: false,
  created_ms: 1_700_000_000_000,
  // Ten minutes out, as the controller writes it: a row with no time left is never sent to a
  // provider, so every test that expects a call needs a live deadline.
  deadline_ms: Date.now() + 600_000,
};

/** A provider answer: the model's text is the JSON document, as the prompt asks. */
const speaks = (text, evidence = "log-1") =>
  chatCompletion(JSON.stringify(analysis(text, evidence)));

/** What the fake provider reports, priced at the fake model's rates: 120 in, 24 out. */
const REPORTED = { input_tokens: 120, output_tokens: 24, cost_micros: 33 };

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

/** A controller over a queue of requests, recording every reservation and settlement. */
const queued = (requests, decision = reserved()) => {
  const settled = [];
  const reservations = [];
  const queue = [...requests];
  return {
    settled,
    reservations,
    impl: {
      next: Effect.sync(() => queue.shift() ?? null),
      claim: (id) =>
        Effect.succeed({
          request: row,
          evidence: "/api/v1/attempts/att_1/ai-context",
          token: { access: "delegated", expires_ms: row.deadline_ms, scopes: ["runs:read"] },
        }),
      evidence: () => Effect.succeed(BUNDLE),
      reserve: (id, held) =>
        Effect.sync(() => {
          reservations.push({ id, held });
          return typeof decision === "function" ? decision(id, held) : decision;
        }),
      settle: (id, outcome, settled_analysis, reason, usage) =>
        Effect.sync(() => {
          settled.push({ id, outcome, analysis: settled_analysis, reason, usage });
        }),
    },
  };
};

const run = async (requests, answer, decision) => {
  const fake = recording(answer);
  const memory = queued(requests, decision);
  const served = await Effect.runPromise(
    serve(config).pipe(
      Effect.provideService(Controller, memory.impl),
      Effect.provideService(HttpClient.HttpClient, fake.client),
    ),
  );
  return {
    served,
    calls: fake.calls,
    settled: memory.settled,
    reservations: memory.reservations,
  };
};

test("an empty queue is a poll that served nothing", async () => {
  const { served, calls } = await run([], () => ({ body: chatCompletion("unused") }));
  assert.deepEqual(served, { served: false });
  assert.deepEqual(calls, []);
});

test("a served request is settled with the decoded analysis, never with the provider's text", async () => {
  const { served, settled } = await run([row], () => ({ body: speaks("the lint step failed") }));
  assert.equal(served.outcome, "completed");
  assert.deepEqual(settled, [
    {
      id: "air_1",
      outcome: "completed",
      analysis: analysis("the lint step failed"),
      reason: null,
      usage: REPORTED,
    },
  ]);
});

test("an answer that is not a schema document ends the request unavailable, storing nothing", async () => {
  const { served, settled } = await run([row], () => ({
    body: chatCompletion('{"schema":"sentinel.ai-analysis/1","summary":"s","claims":[{"text":"t"}]}'),
  }));
  assert.equal(served.outcome, "unavailable");
  assert.match(settled[0].reason, /^schema: /);
  assert.equal(settled[0].analysis, null, "nothing partial is settled");
});

test("prose a model wrapped around the document is a refusal, not an answer", async () => {
  const { served, settled } = await run([row], () => ({
    body: chatCompletion(`Here is the analysis:\n${JSON.stringify(analysis("x"))}`),
  }));
  assert.equal(served.outcome, "unavailable");
  assert.match(settled[0].reason, /^schema: /);
});

test("a citation the schema cannot hold never reaches the controller", async () => {
  const invented = analysis("the lint step failed", "log-999999");
  const document = { ...invented, claims: [{ ...invented.claims[0], citations: [{ attempt: "att_1", evidence: "log-1" }] }] };
  const { served, settled } = await run([row], () => ({ body: chatCompletion(JSON.stringify(document)) }));
  // The attempt id is what the schema checks here; whether the frame exists is the controller's
  // citation check, which drops it before anyone sees the claim.
  assert.equal(served.outcome, "unavailable");
  assert.match(settled[0].reason, /^schema: a citation does not name an attempt$/);
});

test("a provider that fails ends the request as unavailable, never as an answer", async () => {
  const { served, settled } = await run([row], () => ({ status: 503, body: { error: "overloaded" } }));
  assert.equal(served.outcome, "unavailable");
  assert.match(settled[0].reason, /^provider: /);
  assert.equal(settled[0].analysis, null);
});

test("a provider that answers with nothing is a failure, not an empty analysis", async () => {
  const { served, settled } = await run([row], () => ({ body: chatCompletion("   ") }));
  assert.equal(served.outcome, "unavailable");
  assert.match(settled[0].reason, /^provider: .*answered with no text/);
});

test("a request that fails does not stop the loop: the next poll serves the next request", async () => {
  const answers = [
    () => ({ status: 500, body: {} }),
    () => ({ body: speaks("the second request's answer") }),
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
  const fake = recording(() => ({ body: speaks("an answer") }));
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

test("an analysis the controller already has is served without a provider call", async () => {
  const { served, calls, settled, reservations } = await run(
    [row],
    () => ({ body: chatCompletion("a provider that must not be asked") }),
    reused("the lint step failed", "fingerprint"),
  );
  assert.equal(served.outcome, "completed");
  assert.equal(served.reused, true);
  assert.deepEqual(calls, [], "a reused answer contacts no provider");
  assert.equal(reservations.length, 1, "the request says what it would cost before anything runs");
  assert.deepEqual(settled, [
    {
      id: "air_1",
      outcome: "completed",
      analysis: analysis("the lint step failed"),
      reason: null,
      usage: null,
    },
  ]);
});

test("a cached analysis that no longer decodes is not served", async () => {
  const { served, settled } = await run(
    [row],
    () => ({ body: chatCompletion("a provider that must not be asked") }),
    { state: "reused", by: "evidence", analysis: { schema: "other", summary: "s", claims: [] } },
  );
  assert.equal(served.outcome, "unavailable");
  assert.equal(settled[0].analysis, null);
});

test("a second identical request is served from the cache without a second provider call", async () => {
  const decisions = [reserved(), reused("the lint step failed")];
  const fake = recording(() => ({ body: speaks("the lint step failed") }));
  const memory = queued([row, { ...row, id: "air_2" }], () => decisions.shift());
  await Effect.runPromise(
    serve(config).pipe(
      Effect.andThen(serve(config)),
      Effect.provideService(Controller, memory.impl),
      Effect.provideService(HttpClient.HttpClient, fake.client),
    ),
  );
  assert.equal(fake.calls.length, 1, "the second request asked the provider again");
  assert.deepEqual(
    memory.settled.map((entry) => [entry.id, entry.outcome, entry.analysis?.claims[0].text]),
    [
      ["air_1", "completed", "the lint step failed"],
      ["air_2", "completed", "the lint step failed"],
    ],
  );
  // Both requests named the same key, which is what made the second one a reuse.
  assert.deepEqual(memory.reservations[0].held, memory.reservations[1].held);
});

test("a request that does not fit is refused before the provider, with the controller's reason", async () => {
  const reason = "budget: the month has spent 1500 tokens of 1500 and this request asks for 1000";
  const { served, calls, settled } = await run(
    [row],
    () => ({ body: chatCompletion("a provider that must not be asked") }),
    refused(reason),
  );
  assert.equal(served.outcome, "unavailable");
  assert.equal(served.reason, reason);
  assert.equal(served.reused, false);
  assert.deepEqual(calls, [], "a refused request contacts no provider");
  assert.deepEqual(settled, [
    { id: "air_1", outcome: "unavailable", analysis: null, reason, usage: null },
  ]);
});

test("the reservation carries the evidence digest, the prompt version, the model and the maxima", async () => {
  const { reservations } = await run([row], () => ({ body: speaks("an answer") }));
  const held = reservations[0].held;
  assert.equal(held.model, "fake/model");
  assert.equal(held.prompt_version, PROMPT_VERSION);
  assert.match(held.digest, /^[0-9a-f]{64}$/);
  assert.match(held.fingerprint, /^[0-9a-f]{64}$/);
  assert.equal(held.output_tokens, 1_024, "the whole output cap is held");
  assert.ok(held.input_tokens > BUNDLE.length / 3 - 1, "the prompt is counted");
  assert.ok(held.cost_micros > 0, "the maximum is priced at the model's rates");
});
