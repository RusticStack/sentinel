// The evaluation set and its scoring (Y09), against the recording fake provider: the committed set
// is well formed, the scores are what the backlog row names, and the gate refuses what it must.
// No provider is contacted here; a measured record comes from `src/evaluate.ts`.

import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { Effect, Redacted } from "effect";
import * as HttpClient from "effect/http/HttpClient";

import {
  RECORD_SCHEMA,
  SOURCES,
  baseline,
  evidenceIds,
  gate,
  leaks,
  loadCases,
  loadRecords,
  p95,
  run,
  scoreCase,
  setDigest,
  summarize,
} from "../src/evaluation.ts";
import { PROMPT_VERSION } from "../src/service.ts";
import { chatCompletion, model, recording } from "./fake.mjs";

const CASES = loadCases(fileURLToPath(new URL("../eval/cases", import.meta.url)));
const RECORDS = loadRecords(fileURLToPath(new URL("../eval/results.jsonl", import.meta.url)));

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

const answer = (attempt, evidence) => ({
  schema: "sentinel.ai-analysis/1",
  summary: "the seeded failure",
  claims: [{ text: "this line failed", citations: [{ attempt, evidence }] }],
});

/** Runs `cases` against a fake that answers each with `cite(case)`'s evidence identifier. */
const evaluate = async (cases, cite) => {
  const fake = recording((call) => {
    const one = cases.find((candidate) => call.body.includes(candidate.bundle.attempt));
    return { body: chatCompletion(JSON.stringify(answer(one.bundle.attempt, cite(one)))) };
  });
  const record = await Effect.runPromise(
    run(config, "openrouter", cases, "2026-01-01T00:00:00.000Z").pipe(
      Effect.provideService(HttpClient.HttpClient, fake.client),
    ),
  );
  return { record, calls: fake.calls };
};

const observation = (one, analysis, overrides = {}) => ({
  case: one.id,
  analysis,
  reason: analysis === null ? "provider" : null,
  prompts: [JSON.stringify(one.bundle)],
  cost_micros: 100,
  latency_ms: 10,
  ...overrides,
});

const recordOf = (scores, overrides = {}) => ({
  schema: RECORD_SCHEMA,
  recorded: "2026-01-01T00:00:00.000Z",
  provider: "openrouter",
  model: "fake/model",
  prompt_version: PROMPT_VERSION,
  set: setDigest(CASES),
  scores: {
    cases: 7,
    completed: 7,
    error_line_share: 1,
    citation_validity: 1,
    canary_leaks: 0,
    cost_p95_micros: 100,
    latency_p95_ms: 1_000,
    ...scores,
  },
  per_case: [],
  ...overrides,
});

test("the set has a seeded failure from every pilot and the X08 fixture", () => {
  assert.deepEqual([...new Set(CASES.map((one) => one.source))].sort(), [...SOURCES].sort());
  assert.equal(new Set(CASES.map((one) => one.id)).size, CASES.length);
  assert.equal(new Set(CASES.map((one) => one.bundle.attempt)).size, CASES.length);
});

test("every case names an error line its bundle holds, and holds none of its canaries", () => {
  for (const one of CASES) {
    assert.equal(one.bundle.schema, "sentinel.ai-context/1", one.id);
    const known = evidenceIds(one.bundle);
    assert.ok(one.error_evidence.length > 0, one.id);
    for (const id of one.error_evidence) {
      assert.ok(known.has(id), `${one.id}: ${id}`);
    }
    // More to cite than the answer, or citing the error line would prove nothing.
    assert.ok(known.size > one.error_evidence.length + 3, one.id);
    assert.ok(one.canaries.length > 0, one.id);
    assert.equal(leaks(JSON.stringify(one.bundle), one.canaries), 0, one.id);
  }
});

test("the X08 case's failing line is outside its log window", () => {
  const x08 = CASES.find((one) => one.source === "x08");
  assert.deepEqual(x08.error_evidence, ["diag-1"]);
  assert.equal(x08.bundle.bounds.truncated, true);
  assert.equal(x08.bundle.log.complete, false);
});

test("a citation of the error line is a hit; another valid one is not", () => {
  const one = CASES[0];
  const hit = scoreCase(one, observation(one, answer(one.bundle.attempt, one.error_evidence[0])));
  assert.deepEqual(
    [hit.completed, hit.cites_error_line, hit.citations, hit.invalid_citations, hit.leaks],
    [true, true, 1, 0, 0],
  );
  const other = [...evidenceIds(one.bundle)].find((id) => !one.error_evidence.includes(id));
  const miss = scoreCase(one, observation(one, answer(one.bundle.attempt, other)));
  assert.deepEqual([miss.cites_error_line, miss.invalid_citations], [false, 0]);
});

test("a citation the bundle does not hold is invalid, whatever it names", () => {
  const one = CASES[0];
  const absent = scoreCase(one, observation(one, answer(one.bundle.attempt, "log-999999")));
  assert.deepEqual([absent.cites_error_line, absent.invalid_citations], [false, 1]);
  const foreign = scoreCase(
    one,
    observation(one, answer("att_99999999-9999-4999-8999-999999999999", one.error_evidence[0])),
  );
  assert.deepEqual([foreign.cites_error_line, foreign.invalid_citations], [false, 1]);
});

test("an unavailable request cites nothing and is no analysis to price", () => {
  const scores = summarize([
    scoreCase(CASES[0], observation(CASES[0], null, { cost_micros: null, latency_ms: 9_000 })),
    scoreCase(
      CASES[1],
      observation(CASES[1], answer(CASES[1].bundle.attempt, CASES[1].error_evidence[0])),
    ),
  ]);
  assert.deepEqual(scores, {
    cases: 2,
    completed: 1,
    error_line_share: 0.5,
    citation_validity: 1,
    canary_leaks: 0,
    cost_p95_micros: 100,
    latency_p95_ms: 10,
  });
});

test("a canary, an escaped canary and a secret shape in a prompt are each a leak", () => {
  assert.equal(leaks("token canary-1 and canary-1", ["canary-1"]), 2);
  assert.equal(leaks(JSON.stringify({ text: 'a "quoted" value' }), ['a "quoted" value']), 1);
  // Assembled from parts: the committed-key guard reads a whole header in the tree as a key.
  const header = ["-----BEGIN ", "RSA PRIVATE KEY", "-----"].join("");
  assert.equal(leaks(`cat key.pem ${header}`, []), 1);
  assert.equal(leaks(`GITHUB_TOKEN=${"ghp_"}${"a1".repeat(18)}`, []), 1);
  assert.equal(leaks(`aws_access_key_id = ${"AKIA"}IOSFODNN7EXAMPLE`, []), 1);
  assert.equal(leaks("export GITHUB_TOKEN=*** and nothing else", ["canary-1"]), 0);
});

test("p95 is the nearest rank", () => {
  assert.equal(p95([]), null);
  assert.equal(p95([7]), 7);
  assert.equal(p95([5, 1, 4, 2, 3, 7, 6]), 7);
  assert.equal(p95(Array.from({ length: 100 }, (_, index) => index + 1)), 95);
});

test("the gate requires every citation to resolve and nothing to leak, baseline or not", () => {
  assert.deepEqual(gate(recordOf({}), null), []);
  assert.equal(gate(recordOf({ citation_validity: 0.9 }), null).length, 1);
  assert.equal(gate(recordOf({ citation_validity: null }), null).length, 1);
  assert.equal(gate(recordOf({ canary_leaks: 1 }), null).length, 1);
  assert.equal(gate(recordOf({ cases: 0 }), null).length, 1);
});

test("the gate refuses a regression against the same model and prompt version", () => {
  const past = recordOf({ error_line_share: 6 / 7 });
  assert.deepEqual(gate(recordOf({ error_line_share: 6 / 7 }), past), []);
  assert.match(gate(recordOf({ error_line_share: 5 / 7 }), past)[0], /error-line share fell/);
  assert.deepEqual(gate(recordOf({ error_line_share: 6 / 7, cost_p95_micros: 110 }), past), []);
  assert.match(gate(recordOf({ error_line_share: 6 / 7, cost_p95_micros: 111 }), past)[0], /cost p95/);
  assert.match(
    gate(recordOf({ error_line_share: 6 / 7, latency_p95_ms: 1_501 }), past)[0],
    /latency p95/,
  );
  assert.match(
    gate(recordOf({ error_line_share: 6 / 7, cost_p95_micros: null }), past)[0],
    /unmeasured/,
  );
});

test("a baseline is the last record with the same provider, model, prompt version and set", () => {
  const first = recordOf({ error_line_share: 0.5 });
  const second = recordOf({ error_line_share: 0.75 });
  const history = [
    first,
    second,
    recordOf({}, { model: "other/model" }),
    recordOf({}, { prompt_version: "analysis-0" }),
    recordOf({}, { provider: "local" }),
    recordOf({}, { set: "0".repeat(64) }),
  ];
  assert.equal(baseline(history, recordOf({})), second);
  assert.equal(baseline(history, recordOf({}, { model: "new/model" })), null);
});

test("the set served through the service: a model citing each error line scores in full", async () => {
  const { record, calls } = await evaluate(CASES, (one) => one.error_evidence[0]);
  assert.equal(calls.length, CASES.length);
  assert.equal(record.schema, RECORD_SCHEMA);
  assert.equal(record.model, "fake/model");
  assert.equal(record.prompt_version, PROMPT_VERSION);
  assert.equal(record.set, setDigest(CASES));
  assert.equal(record.scores.cases, CASES.length);
  assert.equal(record.scores.completed, CASES.length);
  assert.equal(record.scores.error_line_share, 1);
  assert.equal(record.scores.citation_validity, 1);
  assert.equal(record.scores.canary_leaks, 0);
  // The fake reports 120 input and 24 output tokens at 150,000 and 600,000 micros per million.
  assert.equal(record.scores.cost_p95_micros, 33);
  assert.ok(record.scores.latency_p95_ms >= 0);
  assert.deepEqual(gate(record, null), []);
});

test("the set served through the service: a model citing another line scores nothing", async () => {
  const { record } = await evaluate(CASES, (one) =>
    [...evidenceIds(one.bundle)].find((id) => !one.error_evidence.includes(id)),
  );
  assert.equal(record.scores.error_line_share, 0);
  assert.equal(record.scores.citation_validity, 1);
  assert.match(gate(record, recordOf({}))[0], /error-line share fell/);
});

test("a canary that reaches the provider is counted where the provider would see it", async () => {
  const one = structuredClone(CASES[0]);
  one.bundle.log.frames[0].text = `deploy: token ${one.canaries[0]}\n`;
  const { record, calls } = await evaluate([one], (c) => c.error_evidence[0]);
  assert.ok(calls[0].body.includes(one.canaries[0]));
  assert.equal(record.scores.canary_leaks, 1);
  assert.match(gate(record, null)[0], /canary leakage/);
});

test("every committed record passes the gate against the one before it", () => {
  RECORDS.forEach((record, index) => {
    assert.equal(record.schema, RECORD_SCHEMA);
    assert.deepEqual(gate(record, baseline(RECORDS.slice(0, index), record)), [], record.recorded);
  });
});
