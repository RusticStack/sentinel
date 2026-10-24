// Run with node --test on Node 22.18+, which strips the TypeScript types.
import assert from "node:assert/strict";
import test from "node:test";
import {
  baseUrlProblem, emptyDraft, fragmentToken, githubStanding, INVITATION_STASH_MS, isSetupToken, parseDraft,
  passwordAdvice, serializeDraft, slugProblem, stashInvitation, unstashInvitation,
} from "../app/utils/onboarding.ts";

const HEX = "0123456789abcdef".repeat(4);

test("a link's secret is taken from the fragment only when it is exactly one well-formed token", () => {
  assert.equal(fragmentToken(`#token=${HEX}`, "verification"), HEX);
  assert.equal(fragmentToken(`#token=sntl_${HEX}`, "invitation"), `sntl_${HEX}`);
  assert.equal(fragmentToken(`#token=sntl_${HEX}`, "verification"), null);
  assert.equal(fragmentToken(`#token=${HEX}`, "invitation"), null);
  assert.equal(fragmentToken(`#token=${HEX.slice(1)}`, "verification"), null);
  assert.equal(fragmentToken(`#token=${HEX}&token=${HEX}`, "verification"), null);
  assert.equal(fragmentToken(`?token=${HEX}`, "verification"), null);
  assert.equal(fragmentToken("", "verification"), null);
  assert.equal(fragmentToken(`#token=${HEX}${"x".repeat(600)}`, "verification"), null);
});

test("an invitation parked for GitHub sign-in comes back only within its ten minutes", () => {
  const token = `sntl_${HEX}`;
  const now = 1_700_000_000_000;
  const parked = stashInvitation(token, now);
  assert.equal(unstashInvitation(parked, now + 1), token);
  assert.equal(unstashInvitation(parked, now + INVITATION_STASH_MS - 1), token);
  assert.equal(unstashInvitation(parked, now + INVITATION_STASH_MS), null);
  assert.equal(unstashInvitation(null, now), null);
  assert.equal(unstashInvitation("{not json", now), null);
  assert.equal(unstashInvitation(stashInvitation(HEX, now), now), null);
  assert.equal(unstashInvitation(JSON.stringify({ token, until: now + 10 * INVITATION_STASH_MS }), now), null);
  assert.equal(unstashInvitation(JSON.stringify({ token }), now), null);
});

test("a setup token is 64 hex digits, surrounding spaces forgiven", () => {
  assert.ok(isSetupToken(`  ${HEX}\n`));
  assert.ok(!isSetupToken(`sntl_${HEX}`));
  assert.ok(!isSetupToken(HEX.replace("a", "g")));
});

test("password guidance follows the controller's byte bounds and refuses only spacing", () => {
  assert.equal(passwordAdvice("short").acceptable, false);
  assert.equal(passwordAdvice(" ".repeat(20)).acceptable, false);
  assert.equal(passwordAdvice("€€€€").acceptable, true);
  assert.equal(passwordAdvice("x".repeat(257)).acceptable, false);
  assert.equal(passwordAdvice("a".repeat(256)).acceptable, true);
  const weak = passwordAdvice("aaaaaaaaaaaaaaaa");
  assert.ok(weak.score <= 1 && weak.hints.length > 0, JSON.stringify(weak));
  const strong = passwordAdvice("correct Horse battery 9 staple");
  assert.ok(strong.acceptable && strong.score >= 3, JSON.stringify(strong));
  const named = passwordAdvice("adalovelace-rules-2026", ["ada.lovelace@example.com"]);
  assert.ok(named.hints.some((h) => h.includes("address")), JSON.stringify(named));
});

test("organization names follow the controller's shape", () => {
  for (const ok of ["ab", "my-team", "a1", "x".repeat(63)]) assert.equal(slugProblem(ok), null, ok);
  for (const bad of ["a", "My-Team", "-team", "team-", "my team", "x".repeat(64), "tëam"]) assert.notEqual(slugProblem(bad), null, bad);
});

test("a base URL is an absolute http(s) address without credentials, query or fragment", () => {
  assert.equal(baseUrlProblem(""), null);
  assert.equal(baseUrlProblem("https://ci.example.com"), null);
  assert.notEqual(baseUrlProblem("ci.example.com"), null);
  assert.notEqual(baseUrlProblem("ftp://ci.example.com"), null);
  assert.notEqual(baseUrlProblem("https://user:pw@ci.example.com"), null);
  assert.notEqual(baseUrlProblem("https://ci.example.com/?a=1"), null);
});

test("the stored wizard draft never carries a secret, whatever the object holds", () => {
  const draft = { ...emptyDraft(), email: "ada@example.com", token: HEX, password: "a secret password", resendKey: "re_not_a_real_key", again: "a secret password" };
  const text = serializeDraft(draft);
  for (const secret of [HEX, "a secret password", "re_not_a_real_key"]) assert.ok(!text.includes(secret), secret);
  assert.deepEqual(Object.keys(JSON.parse(text)).sort(), Object.keys(emptyDraft()).sort());
});

test("a stored draft is read back field by field, and anything malformed falls back", () => {
  const back = parseDraft(serializeDraft({ ...emptyDraft(), step: 4, email: "ada@example.com", registration: "closed", tenantCreation: "approved-users", instanceName: "Build farm" }), 6);
  assert.equal(back.step, 4);
  assert.equal(back.email, "ada@example.com");
  assert.equal(back.registration, "closed");
  assert.equal(back.tenantCreation, "approved-users");
  assert.equal(back.instanceName, "Build farm");
  const bad = parseDraft(JSON.stringify({ step: 99, registration: "open", tenantCreation: "everyone", retired: "a field from an older draft", email: 5 }), 6);
  assert.deepEqual(bad, emptyDraft());
  assert.deepEqual(parseDraft("not json", 6), emptyDraft());
  assert.deepEqual(parseDraft(null, 6), emptyDraft());
  assert.deepEqual(parseDraft("x".repeat(9000), 6), emptyDraft());
});

test("a member's GitHub standing: unanswered checks are unknown before anything else", () => {
  assert.equal(githubStanding(undefined), "unconfirmed");
  assert.equal(githubStanding({ confirmed_ms: 5, check_due: true, unanswered: 2 }), "unknown");
  assert.equal(githubStanding({ confirmed_ms: 5, check_due: true, unanswered: 0 }), "checking");
  assert.equal(githubStanding({ confirmed_ms: 5, check_due: false, unanswered: 0 }), "confirmed");
  assert.equal(githubStanding({ confirmed_ms: null, check_due: false, unanswered: 0 }), "unconfirmed");
});
