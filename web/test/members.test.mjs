// Adding a member: a user id adds anyone, a username only changes the role of a member the page holds, and an unknown
// name is refused before any request with words that say what to do (the controller answers it as not_found).
import assert from "node:assert/strict";
import test from "node:test";
import { listComplete, memberTarget, USER_ID } from "../src/lib/members.ts";

const ID = "usr_0b9c7a1e-3f52-4d6a-9a1e-7c2f1d5b8e40";
const OTHER = "usr_5d1e8c34-62aa-4b0f-8e17-3a9c4f20b7d1";
const listed = [{ user: OTHER, username: "rui" }, { user: "usr_11111111-2222-4333-8444-555555555555", username: null }];

test("a user id is accepted as typed, minus the whitespace around it", () => {
  assert.deepEqual(memberTarget(ID, listed, true), { path: ID });
  assert.deepEqual(memberTarget(`  ${ID}\n`, listed, true), { path: ID });
  assert.deepEqual(memberTarget(ID, listed, false), { path: ID });
});

test("a listed member's username resolves to the member's id", () => {
  assert.deepEqual(memberTarget("rui", listed, true), { path: OTHER });
  assert.deepEqual(memberTarget(" rui ", listed, false), { path: OTHER });
});

test("an unknown name is refused with what to do when the list is whole, and goes to the controller when it is not", () => {
  const refused = memberTarget("pat", listed, true);
  assert.ok("problem" in refused && /user id/.test(refused.problem) && /invite/.test(refused.problem), JSON.stringify(refused));
  assert.deepEqual(memberTarget("pat", listed, false), { path: "pat", unlisted: true });
});

test("nothing typed, or something that is only a near miss of an id, is not sent as an id", () => {
  assert.ok("problem" in memberTarget("   ", listed, true));
  assert.ok("problem" in memberTarget("usr_0b9c7a1e", listed, true));
  assert.ok(!USER_ID.test(ID.toUpperCase()), "ids are lower-case, as the controller parses them");
  assert.ok(!USER_ID.test(ID.replace("-4d6a-", "-1d6a-")), "version 4 only");
  assert.ok(USER_ID.test(ID));
});

test("a members read that failed or has another page is not a whole list, so a typed name goes to the controller", () => {
  assert.equal(listComplete({ next: null }), true);
  assert.equal(listComplete({ next: "cursor" }), false);
  assert.equal(listComplete(null), false, "a failed read lists nobody, which is not the same as nobody being a member");
  assert.deepEqual(memberTarget("rui", [], listComplete(null)), { path: "rui", unlisted: true });
});
