// History views: request paths, continuation merging, the marked hit, the signed change and the words a view prints.
import assert from "node:assert/strict";
import test from "node:test";
import { addPage, comparePath, defaultPair, durationsPath, fmtDelta, fmtShare, searchPath, searchWords, splitHit, windowWords } from "../src/lib/history.ts";
import { ATTEMPT, searchSchema, NAME } from "../src/lib/search.ts";

const RESUME = { run: "run_0b9c7a1e-3f52-4d6a-9a1e-7c2f1d5b8e40", attempt: "att_5d1e8c34-62aa-4b0f-8e17-3a9c4f20b7d1", after: 42, carry: "00ab", runs: 7 };
const page = (over = {}) => ({ matches: [], attempts_scanned: 1, scanned_bytes: 100, expired_attempts: 0, missing_logs: 0, runs_in_window: 20, next: null, complete: true, ...over });

test("a repository and job are percent-encoded into the request path and the window defaults to 100 runs", () => {
  assert.equal(durationsPath("acme", "my repo", undefined, undefined), "/api/v1/tenants/acme/repos/my%20repo/durations?runs=100");
  assert.equal(durationsPath("acme", "app", "500", "build & test"), "/api/v1/tenants/acme/repos/app/durations?runs=500&job=build+%26+test");
  assert.equal(comparePath("acme", "app", "att_a", "att_b"), "/api/v1/tenants/acme/repos/app/compare?base=att_a&head=att_b");
});

test("a search continues from exactly the position the last answer named, with the window it has left", () => {
  assert.equal(searchPath("acme", "app", "a b", "50"), "/api/v1/tenants/acme/repos/app/logs/search?q=a+b&runs=50");
  const next = new URL("http://x" + searchPath("acme", "app", "a b", "50", RESUME));
  assert.deepEqual(Object.fromEntries(next.searchParams), { q: "a b", runs: "7", run: RESUME.run, attempt: RESUME.attempt, after: "42", carry: "00ab" });
  const between = new URL("http://x" + searchPath("acme", "app", "x", undefined, { ...RESUME, after: 0, carry: null }));
  assert.equal(between.searchParams.has("carry"), false);
  assert.equal(between.searchParams.get("after"), "0");
});

test("pages add up: lines in order, counters summed, the position and completeness of the last page", () => {
  const first = page({ matches: [{ seq: 1 }], attempts_scanned: 2, scanned_bytes: 10, expired_attempts: 1, next: RESUME, complete: false });
  const second = page({ matches: [{ seq: 2 }], attempts_scanned: 3, scanned_bytes: 5, missing_logs: 2, next: null, complete: true, runs_in_window: 7 });
  const sum = addPage(first, second);
  assert.deepEqual(sum.matches.map((m) => m.seq), [1, 2]);
  assert.deepEqual([sum.attempts_scanned, sum.scanned_bytes, sum.expired_attempts, sum.missing_logs], [5, 15, 1, 2]);
  assert.equal(sum.next, null);
  assert.equal(sum.complete, true);
  assert.equal(sum.runs_in_window, 20, "the window is the one the search began with");
});

test("a hit is cut around the first occurrence of the term, literally and case-sensitively", () => {
  assert.deepEqual(splitHit("expected 200, got 500", "200"), ["expected ", "200", ", got 500"]);
  assert.deepEqual(splitHit("Error error", "error"), ["Error ", "error", ""]);
  assert.deepEqual(splitHit("a.b", "."), ["a", ".", "b"], "a dot is a dot, not a pattern");
  assert.deepEqual(splitHit("a line begun earlier", "needle"), ["a line begun earlier", "", ""]);
  assert.deepEqual(splitHit("text", ""), ["text", "", ""]);
});

test("a change carries its sign in words, and an unmeasured one is a dash", () => {
  assert.equal(fmtDelta(1_500_000_000), "+1.5 s");
  assert.equal(fmtDelta(-300_000_000), "−300 ms");
  assert.equal(fmtDelta(0), "no change");
  assert.equal(fmtDelta(undefined), "—");
  assert.equal(fmtShare(1_000, 120), "+12%");
  assert.equal(fmtShare(1_000, -500), "−50%");
  assert.equal(fmtShare(0, 5), "");
  assert.equal(fmtShare(1_000, undefined), "");
});

test("the window says how many runs it holds and whether that is fewer than asked for", () => {
  assert.equal(windowWords({ requested: 100, runs: 0, oldest_ms: null, newest_ms: null }), "No runs in this repository yet.");
  assert.equal(windowWords({ requested: 100, runs: 12, oldest_ms: 1, newest_ms: 2 }), "The last 12 runs (up to 100 asked for).");
  assert.equal(windowWords({ requested: 1, runs: 1, oldest_ms: 1, newest_ms: 1 }), "The last 1 run.");
  assert.equal(windowWords({ requested: 25, runs: 25, oldest_ms: 1, newest_ms: 2 }), "The last 25 runs.");
});

test("a search says what it read, what retention removed and whether more of the window is left", () => {
  const bytes = (n) => `${n} B`;
  assert.equal(searchWords(page({ attempts_scanned: 1, scanned_bytes: 5, runs_in_window: 1 }), bytes), "Read 1 log (5 B) of the last 1 run. The search covered the whole window.");
  const words = searchWords(page({ attempts_scanned: 4, expired_attempts: 2, missing_logs: 1, complete: false }), bytes);
  assert.match(words, /2 logs were removed by retention and cannot be searched\./);
  assert.match(words, /1 attempt has no stored log\./);
  assert.match(words, /More of the window is left to search\.$/);
});

test("the newest two attempts are the default head and base, and fewer leave the rest unchosen", () => {
  assert.deepEqual(defaultPair([{ attempt: "a" }, { attempt: "b" }, { attempt: "c" }]), { head: "a", base: "b" });
  assert.deepEqual(defaultPair([{ attempt: "a" }]), { head: "a", base: null });
  assert.deepEqual(defaultPair(undefined), { head: null, base: null });
});

test("search parameters of the history views drop anything that is not an attempt id, a name or a number", () => {
  const schema = searchSchema({ repo: [NAME, 100], base: [ATTEMPT, 40] });
  const parsed = schema["~standard"].validate({ repo: "app", base: "att_5d1e8c34-62aa-4b0f-8e17-3a9c4f20b7d1" }).value;
  assert.deepEqual(parsed, { repo: "app", base: "att_5d1e8c34-62aa-4b0f-8e17-3a9c4f20b7d1" });
  const dropped = schema["~standard"].validate({ repo: "../x", base: "att_../../etc" }).value;
  assert.deepEqual(dropped, {});
});
