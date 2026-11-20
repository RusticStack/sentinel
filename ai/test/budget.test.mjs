// What a request reserves before it is made, and what settles it afterwards. The estimate has to be
// a ceiling — an under-count is a budget overspent by the difference — and a price has to be the
// model's own, because the controller never knows one.

import assert from "node:assert/strict";
import test from "node:test";

import { estimateTokens, reportedUsage, reservation } from "../src/budget.ts";
import { model } from "./fake.mjs";

const LIMITS = model("fake/model", 4_096);

test("the prompt estimate is a ceiling over the bytes, not an average", () => {
  assert.equal(estimateTokens(""), 0);
  // Three bytes per token is below what any modern tokenizer achieves on English or code.
  assert.equal(estimateTokens("abc"), 1);
  assert.equal(estimateTokens("abcd"), 2);
  assert.ok(estimateTokens("a".repeat(3_000)) === 1_000);
  // A character outside ASCII counts as a whole token, where a byte ratio would under-count.
  assert.equal(estimateTokens("é".repeat(100)), 100);
});

test("a reservation holds the output cap and prices both sides at the model's rates", () => {
  const held = reservation("x".repeat(3_000), LIMITS);
  assert.equal(held.inputTokens, 1_000);
  assert.equal(held.outputTokens, 4_096, "the whole cap is held, not an expected answer");
  // 1000 * 150000 + 4096 * 600000 micros per million tokens.
  assert.equal(held.costMicros, Math.ceil((1_000 * 150_000 + 4_096 * 600_000) / 1_000_000));
  // A free local endpoint reserves no money while still capping its output.
  const local = reservation("x".repeat(3_000), model("local-model", 512) && {
    ...model("local-model", 512),
    inputMicrosPerMtok: 0,
    outputMicrosPerMtok: 0,
  });
  assert.equal(local.costMicros, 0);
  assert.equal(local.outputTokens, 512);
});

test("reported usage is priced from both counts, and a missing one leaves the cost unstated", () => {
  assert.deepEqual(
    reportedUsage({ text: "an answer", inputTokens: 120, outputTokens: 24 }, LIMITS),
    {
      input_tokens: 120,
      output_tokens: 24,
      cost_micros: Math.ceil((120 * 150_000 + 24 * 600_000) / 1_000_000),
    },
  );
  assert.deepEqual(
    reportedUsage({ text: "an answer", inputTokens: 120, outputTokens: null }, LIMITS),
    { input_tokens: 120, output_tokens: null, cost_micros: null },
    "a price from one reported half would be a guess",
  );
});
