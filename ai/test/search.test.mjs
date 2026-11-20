// The log-search assistant's two calls (Y07): the question becomes a plan, the controller executes
// the plan under the request's delegation, and the answer is written from those results alone.
//
// What is proved here is the shape of the exchange rather than whether a model is good at it: the
// plan reaches the controller before any answer is asked for, the answer's prompt carries the
// controller's result document and nothing else, a plan past its bounds never reaches the
// controller at all, a refused plan ends the question without a second provider call, and one
// reservation covers both calls — the maximum the ledger held before either of them ran.

import assert from "node:assert/strict";
import test from "node:test";
import { Effect, Redacted } from "effect";
import * as HttpClient from "effect/http/HttpClient";

import { Controller } from "../src/controller.ts";
import { PLAN_SCHEMA } from "../src/plan.ts";
import { SEARCH_VERSION, serve } from "../src/service.ts";
import { analysis, chatCompletion, model, recording, reserved } from "./fake.mjs";

const ATTEMPT = "att_11111111-1111-4111-8111-111111111111";
const HIDDEN = "att_22222222-2222-4222-8222-222222222222";
const QUESTION = "Why did the create test get a 500?";

const row = {
  id: "air_2",
  attempt: ATTEMPT,
  kind: "search",
  question: QUESTION,
  provider: "openrouter",
  data_policy: "zero_retention",
  origin: "member",
  state: "queued",
  outcome: null,
  reused: false,
  created_ms: 1_700_000_000_000,
  deadline_ms: 1_700_000_900_000,
};

/** One result document, as the controller serves a plan's reads. */
const RESULTS = {
  schema: "sentinel.ai-search/1",
  request: row.id,
  question: QUESTION,
  reads: [
    {
      kind: "search",
      q: "wanted 201",
      runs: 1,
      lines: [
        {
          attempt: ATTEMPT,
          run: "run_1",
          job: "alpha",
          evidence: "log-2",
          sequence: 2,
          step: 1,
          stream: "stdout",
          text: "create_test.go:42: wanted 201, got 500",
        },
      ],
      truncated: false,
      expired_attempts: 0,
      missing_logs: 0,
    },
  ],
  bounds: { reads: 1, scanned_bytes: 4096, attempts: 1, bytes: 512 },
};

/** The plan the fake model drafts: one literal search. */
const PLAN = { schema: PLAN_SCHEMA, reads: [{ kind: "search", q: "wanted 201", runs: 1, limit: 10 }] };

/** A provider answer: the model's text is the JSON document, as the prompt asks. */
const speaks = (document) => chatCompletion(JSON.stringify(document));

const config = {
  controller: "http://controller.internal:8080",
  grant: Redacted.make("service-grant"),
  models: { openrouter: model("fake/model", 2_048) },
  endpoints: {
    local: { url: "http://127.0.0.1:11434/v1", key: null },
    openrouter: "sk-or-fake",
    anthropic: null,
    openai: null,
  },
  pollMs: 1_000,
};

/**
 * One poll over the search request, with the provider answering `answers` in order and the
 * controller's plan route answering `planReply`.
 */
const run = async ({
  answers,
  planReply = () => ({ state: "ready", results: JSON.stringify(RESULTS) }),
}) => {
  const settled = [];
  const reservations = [];
  const plans = [];
  let providerAt = 0;
  const fake = recording(() => ({ body: answers[Math.min(providerAt++, answers.length - 1)] }));
  const controller = {
    next: Effect.succeed(row),
    claim: () =>
      Effect.succeed({
        request: row,
        evidence: `/api/v1/attempts/${ATTEMPT}/ai-context`,
        token: { access: "delegated", expires_ms: row.deadline_ms, scopes: ["runs:read", "logs:read"] },
      }),
    evidence: () => Effect.die("a log-search request reads no evidence bundle"),
    reserve: (id, held) =>
      Effect.sync(() => {
        reservations.push({ id, held });
        return reserved();
      }),
    plan: (id, delegation, plan) =>
      Effect.sync(() => {
        plans.push({ id, delegation, plan });
        return planReply(id, delegation, plan);
      }),
    settle: (id, outcome, settledAnalysis, reason, usage) =>
      Effect.sync(() => {
        settled.push({ id, outcome, analysis: settledAnalysis, reason, usage });
      }),
  };
  const served = await Effect.runPromise(
    serve(config).pipe(
      Effect.provideService(Controller, controller),
      Effect.provideService(HttpClient.HttpClient, fake.client),
    ),
  );
  return { served, calls: fake.calls, settled, reservations, plans };
};

test("a question is planned, executed under the delegation, and answered from the results", async () => {
  const { served, calls, settled, reservations, plans } = await run({
    answers: [speaks(PLAN), speaks(analysis("the test wanted 201 and got 500", "log-2"))],
  });
  assert.equal(served.outcome, "completed");
  // The reservation came before any provider call, and covers the question and its plan.
  assert.equal(reservations.length, 1);
  assert.equal(reservations[0].held.prompt_version, SEARCH_VERSION);
  assert.equal(reservations[0].held.model, "fake/model");
  assert.ok(reservations[0].held.input_tokens > 0);
  assert.ok(
    reservations[0].held.output_tokens >= 2_048,
    "one hold covers both calls' output",
  );
  // The plan reached the controller under the request's own delegation, as the plan the model wrote.
  assert.equal(plans.length, 1);
  assert.equal(plans[0].delegation, "delegated");
  assert.deepEqual(JSON.parse(plans[0].plan), PLAN);
  // Two provider calls, and the second one is given the result document.
  const provider = calls.filter((call) => call.path === "/api/v1/chat/completions");
  assert.equal(provider.length, 2, JSON.stringify(calls.map((call) => call.path)));
  const first = JSON.parse(provider[0].body);
  const second = JSON.parse(provider[1].body);
  assert.match(first.messages.at(-1).content, /wanted 201|plan/i);
  assert.equal(
    first.messages.at(-1).content.includes(RESULTS.schema),
    false,
    "the first call sees no results: it plans the reads",
  );
  assert.match(second.messages.at(-1).content, /sentinel\.ai-search\/1/);
  assert.match(second.messages.at(-1).content, /wanted 201, got 500/);
  assert.equal(
    second.messages.at(-1).content.includes("sentinel.ai-context/1"),
    false,
    "the answer sees the plan's results, never a bundle of its own",
  );
  // The settlement is the answer, with both calls' reported usage added up.
  assert.equal(settled.length, 1);
  assert.equal(settled[0].outcome, "completed");
  assert.equal(settled[0].analysis.summary, "the test wanted 201 and got 500");
  assert.deepEqual(settled[0].usage, {
    input_tokens: 240,
    output_tokens: 48,
    cost_micros: 66,
  });
});

test("a plan past its bounds never reaches the controller and ends the question with its reason", async () => {
  const tooMany = {
    schema: PLAN_SCHEMA,
    reads: Array.from({ length: 7 }, () => ({ kind: "search", q: "x", runs: 1, limit: 1 })),
  };
  const { served, calls, plans, settled } = await run({ answers: [speaks(tooMany)] });
  assert.equal(served.outcome, "unavailable");
  assert.equal(plans.length, 0, "an out-of-bounds plan is never executed");
  assert.equal(
    calls.filter((call) => call.path === "/api/v1/chat/completions").length,
    1,
    "and no answer is asked for",
  );
  assert.match(settled[0].reason, /^plan: /);
  assert.equal(settled[0].analysis, null);
});

test("a plan naming a read the controller refuses ends the question without an answer call", async () => {
  const { served, calls, settled } = await run({
    answers: [
      speaks({ schema: PLAN_SCHEMA, reads: [{ kind: "context", attempt: HIDDEN }] }),
      speaks(analysis("unreachable", "log-1")),
    ],
    planReply: () => ({
      state: "refused",
      reason: "plan: a read names an attempt this repository does not hold",
      field: "plan[1]",
    }),
  });
  assert.equal(served.outcome, "unavailable");
  assert.equal(
    calls.filter((call) => call.path === "/api/v1/chat/completions").length,
    1,
    "the refusal ends the question: nothing is asked of a model that has no results",
  );
  assert.equal(settled[0].reason, "plan: a read names an attempt this repository does not hold");
});

test("a request that states no question is refused before any provider call", async () => {
  // A row the controller should never write; the process refuses it rather than planning a read to
  // answer nothing.
  const settled = [];
  const plans = [];
  let providerCalls = 0;
  const fake = recording(() => {
    providerCalls += 1;
    return { body: speaks(PLAN) };
  });
  const served = await Effect.runPromise(
    serve(config).pipe(
      Effect.provideService(Controller, {
        next: Effect.succeed({ ...row, question: null }),
        claim: () =>
          Effect.succeed({
            request: { ...row, question: null },
            evidence: `/api/v1/attempts/${ATTEMPT}/ai-context`,
            token: { access: "delegated", expires_ms: row.deadline_ms, scopes: ["logs:read"] },
          }),
        evidence: () => Effect.die("a log-search request reads no evidence bundle"),
        reserve: () => Effect.die("nothing is held for a question nobody asked"),
        plan: (id, delegation, plan) =>
          Effect.sync(() => {
            plans.push(plan);
            return { state: "ready", results: JSON.stringify(RESULTS) };
          }),
        settle: (id, outcome, analysis, reason, usage) =>
          Effect.sync(() => {
            settled.push({ outcome, analysis, reason, usage });
          }),
      }),
      Effect.provideService(HttpClient.HttpClient, fake.client),
    ),
  );
  assert.equal(served.outcome, "unavailable");
  assert.equal(providerCalls, 0);
  assert.equal(plans.length, 0);
  assert.equal(settled[0].reason, "plan: the request states no question");
});
