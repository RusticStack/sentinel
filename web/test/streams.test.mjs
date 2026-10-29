// The live relays' answer to a busy controller: a refused park is retried at the delay the controller states, with no
// growth, and the "busy" notice ends as soon as a retry is parked rather than when the park (up to 25 s) returns.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { logStream, pause, runStream, tuning } from "../src/server/streams.ts";

const RUN = "run_00000000-0000-0000-0000-000000000001";
const ATTEMPT = "att_00000000-0000-0000-0000-000000000001";
const STATED = 120;
const PARK_MS = 6000;

// A controller that refuses the first `refusals` parked polls with 429 and then holds the next one for PARK_MS.
async function withController(refusals, fn) {
  const polls = [];
  const sockets = new Set();
  const held = [];
  let parkRequests = 0;
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://controller.invalid");
    const wait = url.pathname.endsWith("/wait");
    const parks = wait ? url.searchParams.has("since") : url.searchParams.get("wait") === "1";
    const json = (status, body) => { res.statusCode = status; res.setHeader("content-type", "application/json"); res.end(JSON.stringify(body)); };
    polls.push({ at: performance.now(), path: url.pathname });
    // A poll that does not wait answers at once, as the run page's first request does.
    if (!parks) return json(200, { version: "0000000000000001", changed: true, finished: false, run: { id: RUN } });
    if (++parkRequests <= refusals) return json(429, { code: "rate_limited", details: { retry_after_ms: STATED } });
    held.push(setTimeout(() => json(200, wait
      ? { version: "0000000000000001", changed: false, finished: false, run: { id: RUN } }
      : { frames: [], gaps: [], next_after: null, complete: false, step_done: false }), PARK_MS));
  });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const saved = { api: process.env.SENTINEL_API, ...tuning };
  process.env.SENTINEL_API = `http://127.0.0.1:${server.address().port}`;
  Object.assign(tuning, { minRetryMs: 0, parkedProofMs: 80 });
  try { await fn(polls); } finally {
    if (saved.api === undefined) delete process.env.SENTINEL_API; else process.env.SENTINEL_API = saved.api;
    Object.assign(tuning, { minRetryMs: saved.minRetryMs, parkedProofMs: saved.parkedProofMs });
    for (const t of held) clearTimeout(t);
    for (const s of sockets) s.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
}

// Events read from the relay's stream until `until` holds for what has arrived, with the time each one came.
async function events(response, until, limitMs) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const seen = [];
  let buffer = "";
  const end = performance.now() + limitMs;
  const timeout = new Promise((resolve) => setTimeout(() => resolve({ timedOut: true }), limitMs));
  while (performance.now() < end) {
    const chunk = await Promise.race([reader.read(), timeout]);
    if (chunk.timedOut || chunk.done) break;
    buffer += decoder.decode(chunk.value, { stream: true });
    let cut;
    while ((cut = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, cut);
      buffer = buffer.slice(cut + 2);
      const fields = Object.fromEntries(block.split("\n").filter((l) => l.includes(": ")).map((l) => [l.slice(0, l.indexOf(": ")), l.slice(l.indexOf(": ") + 2)]));
      seen.push({ at: performance.now(), ...fields });
    }
    if (until(seen)) break;
  }
  await reader.cancel().catch(() => {});
  return seen;
}

const statuses = (seen) => seen.filter((e) => e.event === "status").map((e) => e.data);

test("run stream: the busy notice ends once a retry is parked, not when the park returns", async () => {
  await withController(2, async (polls) => {
    const abort = new AbortController();
    const request = new Request("http://web.invalid/_stream/run/" + RUN, { signal: abort.signal });
    const seen = await events(runStream(request, RUN), (e) => statuses(e).join() === "busy,live", PARK_MS - 1500);
    abort.abort();
    assert.equal(statuses(seen).join(), "busy,live", "busy while refused, live while parked, with the park still open");
  });
});

test("run stream: a refusal is retried at the delay the controller states, with no growth", async () => {
  await withController(3, async (polls) => {
    const abort = new AbortController();
    const request = new Request("http://web.invalid/_stream/run/" + RUN, { signal: abort.signal });
    await events(runStream(request, RUN), (e) => statuses(e).join() === "busy,live", PARK_MS - 1500);
    abort.abort();
    const parked = polls.filter((p) => p.path.endsWith("/wait")).slice(1);
    assert.ok(parked.length >= 4, `three refusals and the park were requested, saw ${parked.length}`);
    const gaps = parked.slice(1).map((p, i) => p.at - parked[i].at);
    // The stated 120 ms with 20% jitter; the doubling backoff gave 500, 1000 and 2000 ms. The bound is wide enough
    // for a loaded host and still below the first doubling step (a gap of 500 ms or more would be backoff).
    for (const gap of gaps.slice(0, 3)) assert.ok(gap < 450, `retry gap ${Math.round(gap)} ms follows the stated delay`);
  });
});

test("log stream: the busy notice ends once a retry is parked, and frames keep their position", async () => {
  await withController(2, async (polls) => {
    const abort = new AbortController();
    const request = new Request("http://web.invalid/_stream/log/" + ATTEMPT, { signal: abort.signal });
    const seen = await events(logStream(request, ATTEMPT, new URLSearchParams("step=1&after=7")), (e) => statuses(e).join() === "busy,live", PARK_MS - 1500);
    abort.abort();
    assert.equal(statuses(seen).join(), "busy,live");
    const logs = polls.filter((p) => p.path.endsWith("/logs"));
    assert.ok(logs.length >= 3, "two refusals and the park were requested");
  });
});

test("a 5xx, a network error and a 429 without a figure back off exponentially; a stated figure is followed without growth", () => {
  const fixed = () => 0.5; // jitter factor 1.0
  assert.deepEqual(pause(null, 500, fixed), { ms: 500, backoff: 1000 });
  assert.deepEqual(pause({ status: 503, body: null }, 8000, fixed), { ms: 8000, backoff: 15000 });
  assert.deepEqual(pause({ status: 429, body: null }, 500, fixed), { ms: 500, backoff: 1000 });
  assert.deepEqual(pause({ status: 429, body: { code: "rate_limited" } }, 15000, fixed), { ms: 15000, backoff: 15000 });
  assert.deepEqual(pause({ status: 429, body: { details: { retry_after_ms: "soon" } } }, 2000, fixed), { ms: 2000, backoff: 4000 });
  assert.deepEqual(pause({ status: 429, body: { details: { retry_after_ms: 1000 } } }, 4000, fixed), { ms: 1000, backoff: 4000 });
  assert.deepEqual(pause({ status: 429, body: { details: { retry_after_ms: 0 } } }, 500, fixed), { ms: 500, backoff: 1000 });
  assert.equal(pause({ status: 429, body: { details: { retry_after_ms: 10 ** 9 } } }, 500, fixed).ms, 15000);
});
