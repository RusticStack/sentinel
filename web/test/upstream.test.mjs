// Upgrades from the Nuxt release keep working: its variable names are read when the new ones are absent (one release).
import assert from "node:assert/strict";
import test from "node:test";
import { clientIp, sentinelApi } from "../src/server/upstream.ts";

const withEnv = (vars, fn) => {
  const saved = {};
  for (const k of ["SENTINEL_API", "NUXT_SENTINEL_API", "SENTINEL_CLIENT_IP_HEADER", "NUXT_CLIENT_IP_HEADER"]) { saved[k] = process.env[k]; delete process.env[k]; }
  Object.assign(process.env, vars);
  try { fn(); } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
};
const request = (headers) => Object.assign(new Request("http://web.invalid/", { headers }), { runtime: { node: { req: { socket: { remoteAddress: "::ffff:127.0.0.1" } } } } });

test("the controller address: new name, then the Nuxt name, then the default", () => {
  withEnv({}, () => assert.equal(sentinelApi(), "http://127.0.0.1:7080"));
  withEnv({ NUXT_SENTINEL_API: "http://10.0.0.2:7080/" }, () => assert.equal(sentinelApi(), "http://10.0.0.2:7080"));
  withEnv({ NUXT_SENTINEL_API: "http://old:1", SENTINEL_API: "http://new:2" }, () => assert.equal(sentinelApi(), "http://new:2"));
});

test("the client-address header: new name, then the Nuxt name; none trusts no header", () => {
  const r = request({ "x-real-ip": "203.0.113.9", "x-forwarded-for": "198.51.100.7" });
  withEnv({}, () => assert.equal(clientIp(r), ""));
  const direct = Object.assign(new Request("http://web.invalid/"), { runtime: { node: { req: { socket: { remoteAddress: "203.0.113.50" } } } } });
  withEnv({}, () => assert.equal(clientIp(direct), "203.0.113.50"));
  withEnv({ NUXT_CLIENT_IP_HEADER: "x-real-ip" }, () => assert.equal(clientIp(r), "203.0.113.9"));
  withEnv({ NUXT_CLIENT_IP_HEADER: "x-real-ip", SENTINEL_CLIENT_IP_HEADER: "x-forwarded-for" }, () => assert.equal(clientIp(r), "198.51.100.7"));
});
