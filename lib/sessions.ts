/**
 * Server-side session store (Deno KV → local SQLite file).
 *
 * Opaque cookie ID; authoritative record lives in KV. Logout / idle / absolute
 * expiry delete the server record so stolen cookies stop working immediately.
 */
import { sessionSecret } from "./env.ts";
import { appKvPath, getAppKv, setAppKvForTests } from "./kv.ts";
import type { SessionUser } from "../utils.ts";

/** Absolute lifetime from login (OWASP: bound session duration). */
export const SESSION_ABSOLUTE_TTL_MS = 12 * 60 * 60 * 1000;
/** Idle timeout: inactivity closes the session server-side. */
export const SESSION_IDLE_TTL_MS = 2 * 60 * 60 * 1000;

export type SessionRecord = {
  userId: number;
  login: string;
  avatarUrl?: string;
  name?: string | null;
  createdAt: number;
  lastSeenAt: number;
};

export type LoadedSession = {
  id: string;
  user: SessionUser;
  record: SessionRecord;
};

/** Inject an in-memory KV for unit tests; pass null to clear. */
export function setSessionKvForTests(kv: Deno.Kv | null): void {
  setAppKvForTests(kv);
}

export function sessionDbPath(): string {
  return appKvPath();
}

function sessionKey(idHash: string): Deno.KvKey {
  return ["sessions", idHash];
}

/** HMAC-SHA256 of the opaque ID so a DB dump does not yield usable cookies. */
async function hashSessionId(id: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(sessionSecret()),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(id),
  );
  return bytesToBase64Url(new Uint8Array(mac));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll(
    "=",
    "",
  );
}

/** Cryptographically random opaque session ID (not a JWT). */
export function createOpaqueSessionId(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

function remainingAbsoluteMs(record: SessionRecord, now: number): number {
  return record.createdAt + SESSION_ABSOLUTE_TTL_MS - now;
}

function isExpired(record: SessionRecord, now: number): boolean {
  if (now - record.createdAt >= SESSION_ABSOLUTE_TTL_MS) return true;
  if (now - record.lastSeenAt >= SESSION_IDLE_TTL_MS) return true;
  return false;
}

function toUser(record: SessionRecord): SessionUser {
  return {
    id: record.userId,
    login: record.login,
    avatarUrl: record.avatarUrl,
    name: record.name,
  };
}

/**
 * Create a new server session and return the opaque cookie value.
 * Caller must set the httpOnly cookie (and clear any prior session cookie).
 */
export async function createSession(user: SessionUser): Promise<string> {
  const id = createOpaqueSessionId();
  const now = Date.now();
  const record: SessionRecord = {
    userId: user.id,
    login: user.login,
    avatarUrl: user.avatarUrl,
    name: user.name,
    createdAt: now,
    lastSeenAt: now,
  };
  const kv = await getAppKv();
  const idHash = await hashSessionId(id);
  await kv.set(sessionKey(idHash), record, {
    expireIn: SESSION_ABSOLUTE_TTL_MS,
  });
  return id;
}

/** Load session by opaque cookie ID. Expired / unknown → null (and deletes if expired). */
export async function loadSession(
  id: string | undefined,
): Promise<LoadedSession | null> {
  if (!id) return null;
  const kv = await getAppKv();
  const idHash = await hashSessionId(id);
  const entry = await kv.get<SessionRecord>(sessionKey(idHash));
  if (!entry.value) return null;

  const now = Date.now();
  if (isExpired(entry.value, now)) {
    await kv.delete(sessionKey(idHash));
    return null;
  }

  return { id, user: toUser(entry.value), record: entry.value };
}

/**
 * Refresh lastSeen and KV TTL after a successful authenticated request.
 * Returns updated session or null if idle/absolute expiry won the race.
 */
export async function touchSession(
  id: string,
): Promise<LoadedSession | null> {
  const kv = await getAppKv();
  const idHash = await hashSessionId(id);
  const entry = await kv.get<SessionRecord>(sessionKey(idHash));
  if (!entry.value) return null;

  const now = Date.now();
  if (isExpired(entry.value, now)) {
    await kv.delete(sessionKey(idHash));
    return null;
  }

  const updated: SessionRecord = { ...entry.value, lastSeenAt: now };
  const absLeft = remainingAbsoluteMs(updated, now);
  const expireIn = Math.min(absLeft, SESSION_IDLE_TTL_MS);
  if (expireIn <= 0) {
    await kv.delete(sessionKey(idHash));
    return null;
  }

  await kv.set(sessionKey(idHash), updated, { expireIn });
  return { id, user: toUser(updated), record: updated };
}

/** Server-side revoke: logout and non-member paths must call this. */
export async function destroySession(id: string | undefined): Promise<void> {
  if (!id) return;
  const kv = await getAppKv();
  const idHash = await hashSessionId(id);
  await kv.delete(sessionKey(idHash));
}
