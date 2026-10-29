// The relay's refusals: an oversized body is a 413 and an unreachable controller a 502, never a truncated pass-through.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { proxy } from "../src/server/proxy.ts";

const verdict = { kind: "proxy", limit: 1024 };
const withController = async (fn) => {
  const seen = [];
  const server = createServer((req, res) => {
    seen.push(req.url);
    let bytes = 0;
    req.on("data", (chunk) => { bytes += chunk.length; });
    req.on("end", () => { res.setHeader("content-type", "text/plain"); res.end(`got ${bytes}`); });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const saved = process.env.SENTINEL_API;
  process.env.SENTINEL_API = `http://127.0.0.1:${server.address().port}`;
  try { await fn(seen); } finally {
    if (saved === undefined) delete process.env.SENTINEL_API; else process.env.SENTINEL_API = saved;
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
};
const streamed = (size) => new ReadableStream({
  start(controller) { controller.enqueue(new Uint8Array(size)); controller.close(); },
});
const post = (body, headers = {}) => new Request("http://web.invalid/api/v1/x", { method: "POST", body, headers, duplex: "half" });

test("a declared length over the limit is a 413 and never reaches the controller", async () => {
  await withController(async (seen) => {
    const size = verdict.limit + 1;
    const answer = await proxy(post(new Uint8Array(size), { "content-length": String(size) }), "/api/v1/x", verdict);
    assert.equal(answer.status, 413);
    assert.deepEqual(seen, []);
  });
});

test("a body with no declared length is cut off at the limit as a 413", async () => {
  await withController(async () => {
    const answer = await proxy(post(streamed(verdict.limit + 1)), "/api/v1/x", verdict);
    assert.equal(answer.status, 413);
  });
});

test("a body within the limit is relayed whole", async () => {
  await withController(async (seen) => {
    const answer = await proxy(post(streamed(verdict.limit)), "/api/v1/x", verdict);
    assert.equal(answer.status, 200);
    assert.equal(await answer.text(), `got ${verdict.limit}`);
    assert.deepEqual(seen, ["/api/v1/x"]);
  });
});

test("an unreachable controller is a 502", async () => {
  const saved = process.env.SENTINEL_API;
  process.env.SENTINEL_API = "http://127.0.0.1:1";
  try {
    const answer = await proxy(new Request("http://web.invalid/api/v1/x"), "/api/v1/x", verdict);
    assert.equal(answer.status, 502);
  } finally {
    if (saved === undefined) delete process.env.SENTINEL_API; else process.env.SENTINEL_API = saved;
  }
});
