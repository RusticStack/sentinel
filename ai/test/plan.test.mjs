// `sentinel.ai-plan/1` from the process's side: what it accepts, what it refuses, and that the
// document it sends is the canonical one the controller decodes.

import assert from "node:assert/strict";
import test from "node:test";

import {
  decode,
  encode,
  isPlan,
  MAX_MATCHES,
  MAX_NEEDLE,
  MAX_READS,
  MAX_RUNS,
  PLAN_SCHEMA,
} from "../src/plan.ts";

const ATTEMPT = "att_11111111-1111-4111-8111-111111111111";

const plan = (reads) => JSON.stringify({ schema: PLAN_SCHEMA, reads });

test("a plan of both read kinds round-trips through its wire form", () => {
  const reads = [
    { kind: "search", q: "wanted 201, got 500", runs: 20, limit: 10 },
    { kind: "context", attempt: ATTEMPT },
  ];
  const decoded = decode(plan(reads));
  assert.ok(isPlan(decoded));
  assert.deepEqual(JSON.parse(encode(decoded)), { schema: PLAN_SCHEMA, reads });
});

test("prose, a code fence and a field this build does not execute are refused", () => {
  for (const text of [
    `Here is the plan:\n${plan([])}`,
    "```json\n" + plan([]) + "\n```",
    JSON.stringify({ schema: PLAN_SCHEMA, reads: [], confidence: 1 }),
    plan([{ kind: "search", q: "x", runs: 1, limit: 1, grep: "-i" }]),
    plan([{ kind: "artifact", id: "a" }]),
    JSON.stringify({ schema: "sentinel.ai-plan/2", reads: [] }),
  ]) {
    const decoded = decode(text);
    assert.ok(!isPlan(decoded), text);
    assert.match(decoded.reason, /^plan: /);
  }
});

test("a plan past its reads, needle, run window or match count is refused whole", () => {
  for (const reads of [
    Array.from({ length: MAX_READS + 1 }, () => ({ kind: "context", attempt: ATTEMPT })),
    [],
    [{ kind: "search", q: "", runs: 1, limit: 1 }],
    [{ kind: "search", q: "   ", runs: 1, limit: 1 }],
    [{ kind: "search", q: "x".repeat(MAX_NEEDLE + 1), runs: 1, limit: 1 }],
    [{ kind: "search", q: "x", runs: 0, limit: 1 }],
    [{ kind: "search", q: "x", runs: MAX_RUNS + 1, limit: 1 }],
    [{ kind: "search", q: "x", runs: 1, limit: 0 }],
    [{ kind: "search", q: "x", runs: 1, limit: MAX_MATCHES + 1 }],
    [{ kind: "search", q: "x", runs: 1.5, limit: 1 }],
    [{ kind: "context", attempt: "not-an-attempt" }],
  ]) {
    const decoded = decode(plan(reads));
    assert.ok(!isPlan(decoded), JSON.stringify(reads));
  }
  // The bounds themselves are inside: six reads, a full needle and twenty-five matches.
  const widest = decode(
    plan([
      { kind: "search", q: "x".repeat(MAX_NEEDLE), runs: MAX_RUNS, limit: MAX_MATCHES },
      ...Array.from({ length: MAX_READS - 1 }, () => ({ kind: "context", attempt: ATTEMPT })),
    ]),
  );
  assert.ok(isPlan(widest));
});
