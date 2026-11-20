// `sentinel.ai-analysis/1` as this process decodes it: an answer is stored whole or not at all.
//
// The controller decodes the same document again before it stores one, so these are the failures a
// request ends `unavailable` with rather than a settlement the controller would have to refuse.

import assert from "node:assert/strict";
import test from "node:test";

import {
  ANALYSIS_SCHEMA,
  MAX_CLAIMS,
  check,
  decode,
  isAnalysis,
} from "../src/analysis.ts";
import { ATTEMPT, analysis } from "./fake.mjs";

const doc = (overrides = {}) => ({
  schema: ANALYSIS_SCHEMA,
  summary: "the unit step failed on an assertion",
  claims: [
    {
      text: "the assertion compares two values that differ",
      citations: [
        { attempt: ATTEMPT, evidence: "log-42" },
        { attempt: ATTEMPT, evidence: "diag-1" },
      ],
    },
  ],
  ...overrides,
});

test("a well formed answer decodes into the document the controller stores", () => {
  const decoded = decode(JSON.stringify(doc()));
  assert.ok(isAnalysis(decoded));
  assert.equal(decoded.schema, ANALYSIS_SCHEMA);
  assert.equal(decoded.claims[0].citations[1].evidence, "diag-1");
});

test("an answer that is not JSON, or not one object, is refused", () => {
  for (const text of [
    "",
    "the lint step failed",
    "```json\n{\"schema\":\"sentinel.ai-analysis/1\"}\n```",
    "[]",
    "null",
    "{\"schema\":\"sentinel.ai-analysis/1\",\"summary\":\"s\",\"claims\":[]}{}",
  ]) {
    const decoded = decode(text);
    assert.equal(isAnalysis(decoded), false, text);
    assert.match(decoded.reason, /^schema: /, text);
  }
});

test("a partially valid answer is refused, naming what did not decode", () => {
  const partial = doc();
  delete partial.claims[0].citations;
  assert.match(decode(JSON.stringify(partial)).reason, /cites no evidence/);
  assert.match(decode(JSON.stringify(doc({ schema: "sentinel.ai-analysis/2" }))).reason, /another schema/);
  assert.match(decode(JSON.stringify(doc({ summary: "   " }))).reason, /summary/);
  assert.match(decode(JSON.stringify(doc({ claims: [] }))).reason, /claims/);
  assert.match(
    decode(JSON.stringify(doc({ confidence: 0.9 }))).reason,
    /field this version does not: confidence/,
  );
});

test("an extra field inside a claim or a citation is refused", () => {
  const claim = doc();
  claim.claims[0].confidence = "high";
  assert.match(decode(JSON.stringify(claim)).reason, /a claim has a field this version does not/);
  const citation = doc();
  citation.claims[0].citations[0].quote = "assertion failed";
  assert.match(decode(JSON.stringify(citation)).reason, /a citation has a field/);
});

test("a citation that does not name an attempt and a bundle id is refused", () => {
  for (const bad of [
    { attempt: "att_1", evidence: "log-42" },
    { attempt: ATTEMPT, evidence: "log-042" },
    { attempt: ATTEMPT, evidence: "diag-0" },
    { attempt: ATTEMPT, evidence: "diag-21" },
    { attempt: ATTEMPT, evidence: "line-42" },
    { attempt: ATTEMPT, evidence: 42 },
  ]) {
    const document = doc();
    document.claims[0].citations = [bad];
    assert.equal(isAnalysis(decode(JSON.stringify(document))), false, JSON.stringify(bad));
  }
});

test("the bounds the controller keeps are refused here too", () => {
  const tooMany = doc({
    claims: Array.from({ length: MAX_CLAIMS + 1 }, (_, at) => ({
      text: `claim ${at}`,
      citations: [{ attempt: ATTEMPT, evidence: `log-${at + 1}` }],
    })),
  });
  assert.match(decode(JSON.stringify(tooMany)).reason, /claims/);
  const longClaim = doc();
  longClaim.claims[0].text = "x".repeat(1_025);
  assert.match(decode(JSON.stringify(longClaim)).reason, /claim's text/);
  const huge = " ".repeat(8 << 10) + JSON.stringify(doc());
  assert.match(decode(huge).reason, /over the analysis bound/);
});

test("a document the controller stored decodes the same way when it is reused", () => {
  const stored = analysis("the unit step failed");
  const decoded = check(stored);
  assert.ok(isAnalysis(decoded));
  assert.deepEqual(decoded, stored);
  assert.equal(isAnalysis(check({ schema: "other" })), false);
});
