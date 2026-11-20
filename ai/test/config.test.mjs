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
  const config = load({
    ...MINIMAL,
    SENTINEL_AI_MODEL_LOCAL: "qwen2.5-coder",
    SENTINEL_AI_BUDGET_LOCAL: "2048:0:0",
  });
  assert.ok(!(config instanceof ConfigError));
  assert.equal(config.controller, "http://127.0.0.1:8080");
  assert.equal(config.endpoints.local.url, "http://127.0.0.1:11434/v1");
  assert.equal(config.endpoints.openrouter, null);
  assert.deepEqual(config.models.local, {
    id: "qwen2.5-coder",
    maxOutputTokens: 2048,
    inputMicrosPerMtok: 0,
    outputMicrosPerMtok: 0,
  });
  assert.equal(config.models.openrouter, undefined, "a provider with no model is never used");
  assert.equal(config.pollMs, 2000);
});

test("a model with no budget is refused rather than reserving nothing", () => {
  const missing = load({ ...MINIMAL, SENTINEL_AI_MODEL_OPENROUTER: "openai/gpt-fake" });
  assert.ok(missing instanceof ConfigError);
  assert.match(missing.reason, /SENTINEL_AI_BUDGET_OPENROUTER is not set/);

  for (const spec of ["", "1024", "1024:1", "1024:1:2:3", "0:1:2", "1024:1.5:2", "x:1:2", "-1:1:2"]) {
    const config = load({
      ...MINIMAL,
      SENTINEL_AI_MODEL_OPENROUTER: "openai/gpt-fake",
      SENTINEL_AI_BUDGET_OPENROUTER: spec,
    });
    assert.ok(config instanceof ConfigError, spec);
    // The reason names the variable and never prints what it held.
    assert.match(config.reason, /SENTINEL_AI_BUDGET_OPENROUTER/);
    assert.equal(config.reason.includes(spec === "" ? "=" : spec), false, spec);
  }
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
