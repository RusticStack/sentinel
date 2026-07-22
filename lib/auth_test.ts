import { assertEquals, assertNotEquals, assertRejects } from "@std/assert";
import {
  createOAuthState,
  createPkcePair,
  createSession,
  destroySession,
  loadSession,
  openOAuthHandshake,
  sealOAuthHandshake,
  timingSafeEqualString,
  touchSession,
} from "./auth.ts";
import {
  SESSION_ABSOLUTE_TTL_MS,
  SESSION_IDLE_TTL_MS,
  setSessionKvForTests,
} from "./sessions.ts";
import { sessionSecret } from "./env.ts";

Deno.env.set("SESSION_SECRET", "test-session-secret-at-least-32-chars");
Deno.env.set("GITHUB_CLIENT_ID", "test-client-id");
Deno.env.set("GITHUB_CLIENT_SECRET", "test-client-secret");
Deno.env.set("GH_ORG", "test-org");
Deno.env.set("GITHUB_PAT", "ghp_test_pat");

async function withMemoryKv(fn: () => Promise<void>): Promise<void> {
  const kv = await Deno.openKv(":memory:");
  setSessionKvForTests(kv);
  try {
    await fn();
  } finally {
    setSessionKvForTests(null);
    kv.close();
  }
}

Deno.test("createOAuthState returns unique high-entropy values", () => {
  const a = createOAuthState();
  const b = createOAuthState();
  assertEquals(a.length >= 32, true);
  assertNotEquals(a, b);
});

Deno.test("PKCE challenge is S256 of verifier", async () => {
  const { verifier, challenge } = await createPkcePair();
  assertEquals(verifier.length >= 32, true);
  assertEquals(challenge.length >= 32, true);
  assertNotEquals(verifier, challenge);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  let binary = "";
  for (const byte of new Uint8Array(digest)) {
    binary += String.fromCharCode(byte);
  }
  const expected = btoa(binary).replaceAll("+", "-").replaceAll("/", "_")
    .replaceAll("=", "");
  assertEquals(challenge, expected);
});

Deno.test("server session round-trips identity without access token", async () => {
  await withMemoryKv(async () => {
    const user = {
      id: 42,
      login: "octocat",
      avatarUrl: "https://example.com/a.png",
      name: "The Octocat",
    };
    const id = await createSession(user);
    const session = await loadSession(id);
    assertEquals(session?.user.login, "octocat");
    assertEquals(session?.user.id, 42);
    assertEquals(
      Object.prototype.hasOwnProperty.call(session?.user ?? {}, "accessToken"),
      false,
    );
    // Opaque ID is not a JWT
    assertEquals(id.includes("."), false);
  });
});

Deno.test("loadSession rejects unknown and revoked ids", async () => {
  await withMemoryKv(async () => {
    assertEquals(await loadSession("not-a-real-session"), null);
    const id = await createSession({ id: 1, login: "a" });
    await destroySession(id);
    assertEquals(await loadSession(id), null);
  });
});

Deno.test("touchSession refreshes lastSeen; destroy stops reuse", async () => {
  await withMemoryKv(async () => {
    const id = await createSession({ id: 7, login: "runner" });
    const before = await loadSession(id);
    await new Promise((r) => setTimeout(r, 5));
    const touched = await touchSession(id);
    assertEquals(touched?.user.login, "runner");
    assertEquals(
      (touched?.record.lastSeenAt ?? 0) >= (before?.record.lastSeenAt ?? 0),
      true,
    );
    await destroySession(id);
    assertEquals(await touchSession(id), null);
  });
});

Deno.test("SESSION_SECRET is required for session hashing / handshake", async () => {
  await withMemoryKv(async () => {
    const prev = Deno.env.get("SESSION_SECRET");
    Deno.env.delete("SESSION_SECRET");
    try {
      await assertRejects(() => createSession({ id: 1, login: "a" }));
    } finally {
      if (prev) Deno.env.set("SESSION_SECRET", prev);
    }
  });
});

Deno.test("SESSION_SECRET length is enforced", () => {
  const prev = Deno.env.get("SESSION_SECRET");
  Deno.env.set("SESSION_SECRET", "too-short");
  try {
    let threw = false;
    try {
      sessionSecret();
    } catch {
      threw = true;
    }
    assertEquals(threw, true);
  } finally {
    if (prev) Deno.env.set("SESSION_SECRET", prev);
  }
});

Deno.test("timingSafeEqualString matches equal strings only", () => {
  assertEquals(timingSafeEqualString("abc", "abc"), true);
  assertEquals(timingSafeEqualString("abc", "abd"), false);
  assertEquals(timingSafeEqualString("abc", "ab"), false);
});

Deno.test("OAuth handshake seal/open round-trip", async () => {
  const sealed = await sealOAuthHandshake({
    state: "state-value",
    verifier: "verifier-value",
  });
  const opened = await openOAuthHandshake(sealed);
  assertEquals(opened?.state, "state-value");
  assertEquals(opened?.verifier, "verifier-value");
  assertEquals(await openOAuthHandshake("not-a-jwt"), null);
});

Deno.test("session TTL constants are positive and idle < absolute", () => {
  assertEquals(SESSION_ABSOLUTE_TTL_MS > 0, true);
  assertEquals(SESSION_IDLE_TTL_MS > 0, true);
  assertEquals(SESSION_IDLE_TTL_MS < SESSION_ABSOLUTE_TTL_MS, true);
});
