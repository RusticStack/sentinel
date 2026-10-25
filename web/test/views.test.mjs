// Focused regressions for view behavior that has no component test harness.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = (path) => readFileSync(new URL(`../app/${path}`, import.meta.url), "utf8");

test("setup persistence starts only after the stored draft is restored", () => {
  const text = source("pages/setup.vue");
  const mounted = text.slice(text.indexOf("onMounted"), text.indexOf("function focusHeading"));
  assert.ok(mounted.indexOf("Object.assign(draft, stored)") < mounted.indexOf("watch([draft, step], save"));
  assert.ok(mounted.indexOf("step.value = 0") < mounted.indexOf("watch([draft, step], save"));
});

test("forgot-password recovery explains generated usernames and uses email lookup", () => {
  const text = source("pages/forgot-password.vue");
  assert.match(text, /username is generated/);
  assert.match(text, /WHERE users\.email = '&lt;EMAIL&gt;'/);
  assert.match(text, /--username &lt;USERNAME&gt;/);
  assert.doesNotMatch(text, /--username &lt;NAME&gt;/);
});

test("namespace settings failures have an invitation retry action", () => {
  const text = source("components/admin/Invitations.vue");
  assert.match(text, /settingsFailure/);
  assert.match(text, /Could not load namespace settings/);
  assert.match(text, /onClick: \(\) => retrySettings\?\.\(\)/);
  assert.match(source("pages/t/[slug]/admin/[[section]].vue"), /:retry-settings="refreshSettings"/);
});

test("loading service-account grants cannot emit a success toast", () => {
  const text = source("components/admin/ServiceAccounts.vue");
  const load = text.slice(text.indexOf("async function loadGrants"), text.indexOf("async function toggleGrants"));
  assert.match(load, /\), false\)/);
  assert.match(source("composables/useAct.ts"), /if \(successToast\) toast\.add/);
});

test("blob URLs stay alive until shown-once cleanup, not a zero-ms timeout", () => {
  const text = source("components/ShowOnceModal.vue");
  assert.doesNotMatch(text, /setTimeout\(\(\) => URL\.revokeObjectURL\(url\), 0\)/);
  assert.match(text, /onBeforeUnmount\(\(\) => \{[\s\S]*URL\.revokeObjectURL\(blobUrl\.value\)/);
});

test("step-up password availability comes from me/security", () => {
  const text = source("composables/useStepUp.ts");
  assert.match(text, /api<Security>\("\/api\/v1\/me\/security"\)/);
  assert.match(text, /password: security\.password/);
  assert.doesNotMatch(text, /password: !!me\?\.username/);
});

test("a stale 401 cannot override the password-changed destination", () => {
  const text = source("composables/useApi.ts");
  assert.match(text, /if \(reason === "expired" && !me\.value\) return/);
});
