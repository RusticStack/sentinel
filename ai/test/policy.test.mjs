// The provider policy on its own: which provider a data policy may use, and what the request
// carries when it may be made at all. No Effect, no client — the decisions every later path is
// built on.

import assert from "node:assert/strict";
import test from "node:test";
import {
  PROVIDERS,
  admit,
  allows,
  isReadOnly,
  parseDataPolicy,
  parseProvider,
  readOnly,
  READ_SCOPES,
  staysLocal,
} from "../src/policy.ts";

test("local_only allows only the operator's own endpoint", () => {
  assert.deepEqual(
    PROVIDERS.filter((p) => allows("local_only", p)),
    ["local"],
  );
  const refused = admit("local_only", "openrouter", "some/model", 1024);
  assert.equal(refused.reason, "policy");
  assert.equal(refused.provider, "openrouter");
  const local = admit("local_only", "local", "qwen2.5-coder", 1024);
  assert.equal(local.maxOutputTokens, 1024, "the reservation's cap is what the provider is asked for");
  assert.equal(local.ok, undefined);
  assert.equal(local.provider, "local");
  assert.equal(local.zdr, false);
  assert.equal(local.denyCollection, false);
});

test("zero_retention allows what can keep nothing, and refuses what cannot promise it", () => {
  assert.deepEqual(
    PROVIDERS.filter((p) => allows("zero_retention", p)),
    ["local", "openrouter"],
  );
  assert.equal(admit("zero_retention", "anthropic", "claude", 1024).reason, "policy");
  assert.equal(admit("zero_retention", "openai", "gpt", 1024).reason, "policy");
});

test("provider_terms allows every allow-listed provider", () => {
  for (const provider of PROVIDERS) {
    assert.equal(allows("provider_terms", provider), true, provider);
  }
});

test("openrouter always asks for zero retention, and denies collection under zero_retention", () => {
  const zero = admit("zero_retention", "openrouter", "openai/gpt-fake", 1024);
  assert.equal(zero.zdr, true);
  assert.equal(zero.denyCollection, true);
  // The switch is not the tenant's: it is on whatever the data policy says.
  const terms = admit("provider_terms", "openrouter", "openai/gpt-fake", 1024);
  assert.equal(terms.zdr, true);
  assert.equal(terms.denyCollection, false);
  const local = admit("local_only", "local", "phi", 1024);
  assert.equal(local.zdr, false);
});

test("an unknown provider or an empty model is refused as such", () => {
  const unknown = admit("provider_terms", "cohere", "command", 1024);
  assert.equal(unknown.reason, "provider");
  assert.equal(admit("provider_terms", "openai", "   ", 1024).reason, "model");
  assert.equal(admit("provider_terms", "openai", "x".repeat(129), 1024).reason, "model");
  assert.equal(admit("provider_terms", "openai", "gpt\ninjected", 1024).reason, "model");
  assert.equal(admit("provider_terms", "openai", " gpt-4o ", 1024).model, "gpt-4o");
});

test("names parse only when they are the ones the controller serves", () => {
  assert.equal(parseProvider("openrouter"), "openrouter");
  assert.equal(parseProvider("OpenRouter"), null);
  assert.equal(parseProvider("cohere"), null);
  assert.equal(parseDataPolicy("local_only"), "local_only");
  assert.equal(parseDataPolicy("no_retention"), null);
  assert.equal(parseDataPolicy("provider_terms"), "provider_terms");
});

test("a local endpoint is loopback, a private address, or a name only this host resolves", () => {
  for (const local of [
    "http://127.0.0.1:11434/v1",
    "http://localhost:8000/v1",
    "http://[::1]:11434/v1",
    "http://10.1.2.3:8080/v1",
    "http://172.16.0.9:8080/v1",
    "http://172.31.255.1:8080/v1",
    "http://192.168.1.20:8000/v1",
    "http://169.254.10.10:8000/v1",
    "http://vllm-gateway:8080/v1",
    "http://[fd00::2]:8080/v1",
  ]) {
    assert.equal(staysLocal(local), true, local);
  }
  for (const public_unreachable of [
    "https://openrouter.ai/api/v1",
    "https://api.openai.com/v1",
    "https://api.anthropic.com/v1",
    "http://8.8.8.8/v1",
    "http://172.32.0.1:8080/v1",
    "http://203.0.113.9/v1",
    "http://ollama.example.com/v1",
    "ftp://127.0.0.1/v1",
    "not a url",
    "",
  ]) {
    assert.equal(staysLocal(public_unreachable), false, public_unreachable);
  }
});

test("the delegated scope set is the read-only half of a requester's scopes", () => {
  const requester = ["runs:read", "runs:write", "logs:read", "secrets:write", "tenant:admin"];
  assert.deepEqual(readOnly(requester), ["runs:read", "logs:read"]);
  assert.deepEqual(readOnly(["runs:write", "cache:write"]), []);
  assert.equal(isReadOnly(readOnly(requester)), true);
  assert.equal(isReadOnly(requester), false);
  assert.equal(isReadOnly([]), true);
  assert.equal(READ_SCOPES.includes("ai:context"), false);
});
