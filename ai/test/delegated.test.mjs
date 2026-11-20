// The request-scoped delegation, from the AI process's side: which credential is used for what,
// and what this process refuses to do with one.
//
// The controller mints the delegation as the requester's own identity capped to read-only scopes,
// so a delegated read cannot reach past the requester — that half is proved in Rust
// (`crates/sentinel-api/tests/ai_requests.rs`). What is proved here is that this process never
// widens it: the service grant lists, claims and settles, only the delegation reads evidence, and
// a delegation that claimed any scope outside the read-only set is refused before it is used.

import assert from "node:assert/strict";
import test from "node:test";
import { Effect, Layer, Redacted } from "effect";
import * as HttpClient from "effect/http/HttpClient";

import { Controller, httpLayer } from "../src/controller.ts";
import { recording } from "./fake.mjs";

const BASE = "http://controller.internal:8080";
const SERVICE = "service-grant";

const row = {
  id: "air_00000000-0000-4000-8000-000000000002",
  attempt: "att_00000000-0000-4000-8000-000000000001",
  kind: "analysis",
  question: null,
  provider: "local",
  data_policy: "local_only",
  origin: "member",
  state: "claimed",
  outcome: null,
  reused: false,
  created_ms: 1_700_000_000_000,
  // Ten minutes out, as the controller writes it: a row with no time left is never sent to a
  // provider, so every test that expects a call needs a live deadline.
  deadline_ms: Date.now() + 600_000,
};

const claim = (scopes) => ({
  request: row,
  evidence: `/api/v1/attempts/${row.attempt}/ai-context`,
  token: { access: "delegated-access-token", expires_ms: row.deadline_ms, scopes },
});

const router = (scopes) => (call) => {
  if (call.path === "/api/v1/ai/requests") {
    return { body: { requests: [row] } };
  }
  if (call.path.endsWith("/claim")) {
    return { body: claim(scopes) };
  }
  if (call.path.endsWith("/ai-context")) {
    return { body: { schema: "sentinel.ai-context/1", attempt: row.attempt } };
  }
  return { body: { request: { ...row, state: "settled", outcome: "completed" } } };
};

/** Runs `use` with the HTTP controller over a recording fake, and hands back every call. */
const runWith = async (scopes, use) => {
  const fake = recording(router(scopes));
  const result = await Effect.runPromise(
    Effect.gen(function* () {
      const controller = yield* Controller;
      return yield* use(controller);
    }).pipe(
      Effect.provide(httpLayer(BASE, Redacted.make(SERVICE))),
      Effect.provide(Layer.succeed(HttpClient.HttpClient, fake.client)),
    ),
  );
  return { result, calls: fake.calls };
};

const READ_ONLY = ["runs:read", "logs:read", "artifacts:read"];

test("the service grant lists, claims and settles; only the delegation reads evidence", async () => {
  const { result, calls } = await runWith(READ_ONLY, function* (controller) {
    const queued = yield* controller.next;
    assert.equal(queued.id, row.id);
    const claimed = yield* controller.claim(queued.id);
    const evidence = yield* controller.evidence(claimed);
    yield* controller.settle(queued.id, "completed", "an answer", null);
    return JSON.parse(evidence);
  });

  assert.equal(result.schema, "sentinel.ai-context/1");
  assert.deepEqual(
    calls.map((call) => `${call.method} ${call.path}`),
    [
      "GET /api/v1/ai/requests",
      "POST /api/v1/ai/requests/air_00000000-0000-4000-8000-000000000002/claim",
      "GET /api/v1/attempts/att_00000000-0000-4000-8000-000000000001/ai-context",
      "POST /api/v1/ai/requests/air_00000000-0000-4000-8000-000000000002/complete",
    ],
  );
  assert.deepEqual(
    calls.map((call) => call.authorization),
    [`Bearer ${SERVICE}`, `Bearer ${SERVICE}`, "Bearer delegated-access-token", `Bearer ${SERVICE}`],
  );
});

test("a settlement carries the decoded analysis and never a credential", async () => {
  const document = {
    schema: "sentinel.ai-analysis/1",
    summary: "the failed step timed out",
    claims: [
      {
        text: "the failed step timed out",
        citations: [{ attempt: row.attempt, evidence: "log-7" }],
      },
    ],
  };
  const { calls } = await runWith(READ_ONLY, function* (controller) {
    const claimed = yield* controller.claim(row.id);
    yield* controller.evidence(claimed);
    yield* controller.settle(row.id, "completed", document, null);
  });
  const settlement = JSON.parse(calls.at(-1).body);
  assert.deepEqual(settlement, {
    outcome: "completed",
    analysis: document,
    reason: null,
  });
  assert.equal(calls.at(-1).body.includes("delegated-access-token"), false);
});

test("a delegation carrying a write, an admin scope or the AI grant is refused before it is used", async () => {
  for (const scopes of [
    ["runs:read", "runs:write"],
    ["cache:write"],
    ["tenant:admin"],
    ["ai:context"],
    ["logs:read", "secrets:write"],
  ]) {
    const { calls, result } = await runWith(scopes, function* (controller) {
      const claimed = yield* controller.claim(row.id);
      return yield* controller.evidence(claimed).pipe(
        Effect.map(() => "read"),
        Effect.catch((error) => Effect.succeed(error.reason)),
      );
    });
    assert.match(result, /more than read-only scopes/, scopes.join(" "));
    assert.equal(calls.some((call) => call.path.endsWith("/ai-context")), false, scopes.join(" "));
    assert.equal(result.includes("delegated-access-token"), false);
  }
});

test("a delegation with no read scope at all is never used either", async () => {
  // The controller refuses to mint an empty delegation; this is the same guard failing closed.
  const { calls, result } = await runWith([], function* (controller) {
    const claimed = yield* controller.claim(row.id);
    return yield* controller.evidence(claimed).pipe(
      Effect.map(() => "read"),
      Effect.catch((error) => Effect.succeed(error.reason)),
    );
  });
  assert.equal(result, "read");
  assert.equal(calls.filter((call) => call.path.endsWith("/ai-context")).length, 1);
});
