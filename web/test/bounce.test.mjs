// The return from GitHub starts on another site, where the Strict session cookie is withheld: the two return pages
// answer such a navigation with a same-origin refresh, and nothing else.
import assert from "node:assert/strict";
import test from "node:test";
import { bounceFor } from "../src/server/bounce.ts";

const STATE = "0123456789abcdef".repeat(4);
const cross = { "sec-fetch-site": "cross-site", "sec-fetch-dest": "document", "sec-fetch-mode": "navigate" };
const get = (path, headers = cross, method = "GET") => new Request(`http://web.invalid${path}`, { method, headers });
const refreshOf = async (response) => {
  const html = await response.text();
  const match = html.match(/<meta http-equiv="refresh" content="0;url=([^"]*)">/);
  assert.ok(match, html);
  return match[1].replace(/&amp;/g, "&");
};

test("a cross-site arrival at the created page is sent on to the same address, nothing else kept", async () => {
  const response = bounceFor(get(`/setup/github/created?code=manifestcode0123&state=${STATE}&extra=1&next=https://evil.example`));
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /^text\/html/);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.match(response.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal(await refreshOf(response), `/setup/github/created?code=manifestcode0123&state=${STATE}`);
});

test("a cross-site arrival at the installed page keeps the installation, the action and the state", async () => {
  const response = bounceFor(get(`/setup/github/installed?installation_id=9001&setup_action=install&state=${STATE}`));
  assert.equal(await refreshOf(response), `/setup/github/installed?installation_id=9001&setup_action=install&state=${STATE}`);
  const request = bounceFor(get(`/setup/github/installed?setup_action=request&state=${STATE}`));
  assert.equal(await refreshOf(request), `/setup/github/installed?setup_action=request&state=${STATE}`);
});

test("a value of the wrong shape is dropped, and nothing is reflected unescaped", async () => {
  const response = bounceFor(get(`/setup/github/created?code=%22%3E%3Cscript%3Ealert(1)%3C/script%3E&state=${STATE}`));
  const html = await response.clone().text();
  assert.ok(!html.includes("<script"), html);
  assert.ok(!html.includes("alert"), html);
  assert.equal(await refreshOf(response), `/setup/github/created?state=${STATE}`);
  const bad = bounceFor(get("/setup/github/installed?installation_id=0&setup_action=delete&state=short"));
  assert.equal(await refreshOf(bad), "/setup/github/installed");
});

test("the refresh target is relative, so there is no open redirect", async () => {
  for (const path of ["/setup/github/created?code=a&state=" + STATE, "/setup/github/installed?installation_id=1&setup_action=install&state=" + STATE]) {
    const target = await refreshOf(bounceFor(get(path)));
    assert.ok(target.startsWith("/setup/github/") && !target.startsWith("//"), target);
  }
});

test("a same-origin navigation, one with no fetch metadata, another method or another path is never bounced", () => {
  const path = `/setup/github/created?code=abc&state=${STATE}`;
  assert.equal(bounceFor(get(path, { ...cross, "sec-fetch-site": "same-origin" })), null);
  assert.equal(bounceFor(get(path, { ...cross, "sec-fetch-site": "none" })), null);
  assert.equal(bounceFor(get(path, { ...cross, "sec-fetch-site": "same-site" })), null);
  assert.equal(bounceFor(get(path, {})), null);
  assert.equal(bounceFor(get(path, { ...cross, "sec-fetch-dest": "iframe" })), null);
  assert.equal(bounceFor(get(path, cross, "POST")), null);
  assert.equal(bounceFor(get(`/setup/github?code=abc`, cross)), null);
  assert.equal(bounceFor(get(`/setup/github/created/extra?code=abc`, cross)), null);
  assert.equal(bounceFor(get(`/t/acme`, cross)), null);
});
