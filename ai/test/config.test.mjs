// The configuration: what the process refuses to start with, and that a refusal names the
// variable rather than its value.

import assert from "node:assert/strict";
import test from "node:test";
import { ConfigError, load } from "../src/config.ts";

const MINIMAL = {
  SENTINEL_AI_CONTROLLER: "http://127.0.0.1:8080",
  SENTINEL_AI_TOKEN: "an-ai-service-grant",
};

test("the smallest usable configuration is a controller, a grant and a local endpoint", () => {
  const config = load({ ...MINIMAL, SENTINEL_AI_MODEL_LOCAL: "qwen2.5-coder" });
  assert.ok(!(config instanceof ConfigError));
  assert.equal(config.controller, "http://127.0.0.1:8080");
  assert.equal(config.endpoints.local.url, "http://127.0.0.1:11434/v1");
  assert.equal(config.endpoints.openrouter, null);
  assert.equal(config.models.local, "qwen2.5-coder");
  assert.equal(config.pollMs, 2000);
});

test("a missing controller, grant or unfitting endpoint is refused by name", () => {
  const missingController = load({ SENTINEL_AI_TOKEN: "x" });
  assert.ok(missingController instanceof ConfigError);
  assert.match(missingController.reason, /SENTINEL_AI_CONTROLLER is not set/);

  const missingGrant = load({ SENTINEL_AI_CONTROLLER: "http://127.0.0.1:8080" });
  assert.ok(missingGrant instanceof ConfigError);
  assert.match(missingGrant.reason, /SENTINEL_AI_TOKEN is not set/);

  const notAUrl = load({ ...MINIMAL, SENTINEL_AI_CONTROLLER: "controller:8080" });
  assert.ok(notAUrl instanceof ConfigError);
  assert.match(notAUrl.reason, /SENTINEL_AI_CONTROLLER must be an http/);

  const publicLocal = load({ ...MINIMAL, SENTINEL_AI_LOCAL_URL: "https://llm.example.com/v1" });
  assert.ok(publicLocal instanceof ConfigError);
  assert.match(publicLocal.reason, /inside the operator's own network/);
});

test("a poll interval that would spin is refused, and the refused value is not echoed", () => {
  for (const value of ["0", "99", "2500.5", "soon", "-1000"]) {
    const config = load({ ...MINIMAL, SENTINEL_AI_POLL_MS: value });
    assert.ok(config instanceof ConfigError, value);
    assert.match(config.reason, /SENTINEL_AI_POLL_MS/);
    // The reason names the variable and never prints what it held.
    assert.equal(config.reason.includes("="), false, value);
  }
  assert.equal(load({ ...MINIMAL, SENTINEL_AI_POLL_MS: "250" }).pollMs, 250);
});
