// The migration wizard's own decisions: the request paths, the pairs a parity report compares, the
// pre-switch document a native rollback restores, and the refusal words each step shows.
import assert from "node:assert/strict";
import test from "node:test";
import { ApiError } from "../src/lib/api.ts";
import {
  mayApply, parityPairs, preSwitchDocument, parityPath, previewPath, pullRequestPath, refusalWords,
  rollbackPath, switchPath, tenantPath, workflowsPath, STEPS,
} from "../src/lib/migration.ts";

test("every request the wizard makes is a route the controller serves, with its identifiers encoded", () => {
  assert.equal(tenantPath("acme"), "/api/v1/tenants/acme/migration");
  assert.equal(workflowsPath("acme", "widget"), "/api/v1/tenants/acme/repos/widget/migration/workflows");
  assert.equal(workflowsPath("acme", "widget", "0123456789abcdef0123456789abcdef01234567"),
    "/api/v1/tenants/acme/repos/widget/migration/workflows?commit=0123456789abcdef0123456789abcdef01234567");
  assert.equal(previewPath("acme", "my repo"), "/api/v1/tenants/acme/repos/my%20repo/migration/preview");
  assert.equal(pullRequestPath("acme", "w"), "/api/v1/tenants/acme/repos/w/migration/pull-request");
  assert.equal(switchPath("acme", "w"), "/api/v1/tenants/acme/repos/w/migration/switch");
  assert.equal(parityPath("acme", "w"), "/api/v1/tenants/acme/repos/w/migration/parity");
  assert.equal(rollbackPath("acme", "w"), "/api/v1/tenants/acme/repos/w/migration/rollback");
});

test("the step list is the order the migration happens, and nothing ahead of the answered step is claimed", () => {
  assert.deepEqual(STEPS.map((s) => s.id),
    ["connect", "repositories", "analysis", "preview", "pull-request", "shadow", "switch", "rollback"]);
  assert.equal(STEPS[0].label, "Connect");
});

test("runner mode compares the copies the shadow pull request added", () => {
  const pairs = parityPairs("runner", "abc123", {
    mode: "runner",
    shadow: [{ job: "build", original: "build", name: "sentinel / build", class: "sentinel-4vcpu-ubuntu-2404" }],
  });
  assert.deepEqual(pairs, [{ sha: "abc123", original: "build", shadow: "sentinel / build" }]);
});

test("the native path compares the checks the required-check change replaces", () => {
  const pairs = parityPairs("native", "abc123", {
    mode: "native",
    settings: { change: { added: [], removed: [], replaced: [{ context: "build", check: "sentinel / build" }] } },
  });
  assert.deepEqual(pairs, [{ sha: "abc123", original: "build", shadow: "sentinel / build" }]);
  assert.deepEqual(parityPairs("native", "abc123", null), [], "no preview, no pair");
});

test("the pre-switch document is the set the switch's preview read, contexts and strict as stated", () => {
  const document = preSwitchDocument({
    before: { required: ["build", "mac"], strict: true },
    change: { added: [], removed: [], replaced: [] },
  });
  assert.deepEqual(document, { required_checks: { strict: true, checks: [{ context: "build" }, { context: "mac" }] } });
});

test("the change is Sentinel's only with both the tenant's opt-in and the installation's grant", () => {
  assert.equal(mayApply({ permitted: { settings: true, administration: true } }), true);
  assert.equal(mayApply({ permitted: { settings: false, administration: true } }), false);
  assert.equal(mayApply({ permitted: { settings: true, administration: false } }), false);
  assert.equal(mayApply({ permitted: { settings: true, administration: true, reason: "unprotected" } }), false);
  assert.equal(mayApply(null), false);
});

test("a refusal is the controller's own words: its reason, the permissions it names and the checks it names", () => {
  const off = new ApiError(409, { code: "conflict", message: "guided migration is off for this tenant", details: { reason: "off" } });
  assert.equal(refusalWords(off), "guided migration is off for this tenant: guided migration is off for this tenant");
  const missing = new ApiError(409, { code: "conflict", message: "the GitHub App's installations do not grant what a migration writes with", details: { missing: ["contents", "workflows"] } });
  assert.match(refusalWords(missing), /still lack contents, workflows$/);
  const moving = new ApiError(409, { code: "conflict", message: "a required check names one of the copies the switch drops", details: { reason: "required_check", checks: ["sentinel / build"] } });
  assert.match(refusalWords(moving), /the checks: sentinel \/ build$/);
  const plain = new ApiError(400, { code: "invalid_request", message: "commit is not a full commit id", details: {} });
  assert.equal(refusalWords(plain), "commit is not a full commit id: commit is not a full commit id");
});
