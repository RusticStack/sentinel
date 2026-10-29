// Run with node --test on Node 22.18+, which strips the TypeScript types.
import assert from "node:assert/strict";
import test from "node:test";
import { classifyProxyPath, clientAddress } from "../src/server/guard.ts";
import { pendingReturn, RETURN_SECONDS, returnCookie, sameOriginPath } from "../src/lib/redirect.ts";

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

test("encoded query strings on proxied paths are not ambiguous", () => {
  for (const p of [
    "/oauth/authorize?redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb",
    "/auth/github/callback?next=%2Ft%2Facme",
    "/api/v1/runs?q=100%25&dir=a%5Cb&p=%2E%2E%2Fx",
  ]) assert.equal(classifyProxyPath(p, "GET").kind, "proxy", p);
  assert.equal(classifyProxyPath("/api/v1/%2e%2e/metrics?a=%2F", "GET").kind, "reject");
});

test("body ceilings follow the controller's limits", () => {
  assert.equal(classifyProxyPath("/api/v1/runs", "POST").limit, 1 << 20);
  assert.equal(classifyProxyPath("/api/v1/uploads/upl_1?offset=0", "PUT").limit, 8 << 20);
  assert.equal(classifyProxyPath("/api/v1/hooks/github", "POST").limit, 4 << 20);
});

test("the client address never comes from a client-chosen entry", () => {
  assert.equal(clientAddress("203.0.113.5", undefined), "203.0.113.5");
  for (const proxy of ["127.0.0.1", "10.0.0.2", "172.20.1.1", "192.168.1.9", "169.254.1.1", "::1", "fd00::2", "fe80::1"]) {
    assert.equal(clientAddress(proxy, undefined), "", `${proxy} is a proxy hop, not a client`);
    assert.equal(clientAddress(proxy, "garbage"), "", proxy);
  }
  assert.equal(clientAddress("172.32.0.1", undefined), "172.32.0.1");
  assert.equal(clientAddress("10.0.0.2", "6.6.6.6, 203.0.113.9"), "203.0.113.9");
  assert.equal(clientAddress("10.0.0.2", "[2001:db8::1]"), "2001:db8::1");
  assert.equal(clientAddress("198.51.100.4", "garbage"), "198.51.100.4");
  assert.equal(clientAddress(undefined, undefined), "");
});

test("next must be a same-origin path", () => {
  assert.equal(sameOriginPath("/t/acme/runs?a=1"), "/t/acme/runs?a=1");
  for (const bad of ["//evil.com", "/\\evil.com", "https://evil.com", "evil", "/a\nb", undefined, ["/x"], "/" + "a".repeat(3000)])
    assert.equal(sameOriginPath(bad), "/", String(bad).slice(0, 20));
});

test("a pending return is a short-lived same-origin path cookie the server can read", () => {
  const set = returnCookie("/invitations/accept", true);
  assert.match(set, /^sentinel-return=%2Finvitations%2Faccept; /);
  assert.ok(set.includes("; Path=/;") && set.includes(`; Max-Age=${RETURN_SECONDS};`) && set.includes("; SameSite=Lax") && set.endsWith("; Secure"), set);
  assert.equal(RETURN_SECONDS, 600);
  assert.ok(!returnCookie("/account", false).includes("Secure"));
  assert.match(returnCookie("//evil.com", true), /^sentinel-return=%2F; /);
  assert.match(returnCookie("/a;b=c d", false), /^sentinel-return=%2Fa%3Bb%3Dc%20d; /);
  assert.match(returnCookie(null, false), /^sentinel-return=; Path=\/; Max-Age=0; /);
});

test("a pending return is followed only to a page other than `/`", () => {
  assert.equal(pendingReturn("/invitations/accept"), "/invitations/accept");
  assert.equal(pendingReturn("/t/acme/runs?a=1"), "/t/acme/runs?a=1");
  for (const none of ["/", "/?x=1", "/#a", "//evil.com", "https://evil.com", "", null, undefined, true])
    assert.equal(pendingReturn(none), null, String(none));
});
