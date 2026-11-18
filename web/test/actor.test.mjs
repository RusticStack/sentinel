// A manual run names the account that started it; a webhook run says nothing about who sent it.
import assert from "node:assert/strict";
import test from "node:test";
import { startedBy } from "../src/lib/actor.ts";

const USER = "usr_0b9c7a1e-3f52-4d6a-9a1e-7c2f1d5b8e40";

test("a manual run reads 'Started by' and the account's name", () => {
  assert.equal(startedBy({ actor: { user_id: USER, display_name: "Alice Example" } }), "Started by Alice Example");
});

test("an account the controller no longer names shows its short id, never an empty name", () => {
  assert.equal(startedBy({ actor: { user_id: USER, display_name: null } }), "Started by usr_0b9c7a1e");
  assert.equal(startedBy({ actor: { user_id: USER, display_name: "" } }), "Started by usr_0b9c7a1e");
});

test("a webhook run has no actor and the page shows nothing", () => {
  assert.equal(startedBy({}), null);
  assert.equal(startedBy({ actor: undefined }), null);
});
