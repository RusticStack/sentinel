// Pure guard logic, run with `node --test test/*.test.mjs` on the
// verification VPS (Node 22.18+ strips the TypeScript types).
import assert from "node:assert/strict";
import test from "node:test";
import { classifyProxyPath, clientAddress } from "../server/utils/guard.ts";
import { sameOriginPath } from "../app/utils/redirect.ts";

test("controller paths proxy and others pass", () => {
  assert.equal(classifyProxyPath("/api/v1/runs?x=1", "GET").kind, "proxy");
  assert.equal(classifyProxyPath("/mcp", "POST").kind, "proxy");
  assert.equal(classifyProxyPath("/t/acme", "GET").kind, "pass");
  assert.equal(classifyProxyPath("/_stream/run/run_x", "GET").kind, "pass");
});

test("ambiguous paths that could reach the controller are refused", () => {
  for (const p of [
    "/api/v1/../metrics", "/api/v1/%2e%2e/metrics", "/api/v1/%2E%2e/x", "/api/v1/..\\metrics",
    "/api/v1//runs", "/api/v1/a%2fb", "/api/v1/./runs", "//api/v1/runs", "/x/../api/v1/runs",
    "/%2e/api/v1/runs", "/api/v1/runs%00", "/api/v1/ru\nns",
  ]) assert.equal(classifyProxyPath(p, "GET").kind, "reject", p);
  assert.equal(classifyProxyPath("/t/../login", "GET").kind, "pass");
});

test("body ceilings follow the controller's limits", () => {
  assert.equal(classifyProxyPath("/api/v1/runs", "POST").limit, 1 << 20);
  assert.equal(classifyProxyPath("/api/v1/uploads/upl_1?offset=0", "PUT").limit, 8 << 20);
  assert.equal(classifyProxyPath("/api/v1/hooks/github", "POST").limit, 4 << 20);
});

test("the client address never comes from a client-chosen entry", () => {
  assert.equal(clientAddress("10.0.0.2", undefined), "10.0.0.2");
  assert.equal(clientAddress("10.0.0.2", "6.6.6.6, 203.0.113.9"), "203.0.113.9");
  assert.equal(clientAddress("10.0.0.2", "[2001:db8::1]"), "2001:db8::1");
  assert.equal(clientAddress("10.0.0.2", "garbage"), "10.0.0.2");
  assert.equal(clientAddress(undefined, undefined), "");
});

test("next must be a same-origin path", () => {
  assert.equal(sameOriginPath("/t/acme/runs?a=1"), "/t/acme/runs?a=1");
  for (const bad of ["//evil.com", "/\\evil.com", "https://evil.com", "evil", "/a\nb", undefined, ["/x"], "/" + "a".repeat(3000)])
    assert.equal(sameOriginPath(bad), "/", String(bad).slice(0, 20));
});
