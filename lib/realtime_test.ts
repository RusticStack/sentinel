/**
 * Unit tests for realtime protocol helpers (backoff + message parse).
 */
import { assertEquals, assertGreater, assertLessOrEqual } from "@std/assert";
import {
  BACKOFF_BASE_MS,
  BACKOFF_MAX_MS,
  nextBackoffMs,
  parseWsMessage,
} from "./realtime.ts";

Deno.test("nextBackoffMs doubles until max with deterministic random", () => {
  const rand = () => 0.5; // zero jitter when centered
  assertEquals(nextBackoffMs(0, { random: rand }), BACKOFF_BASE_MS);
  assertEquals(nextBackoffMs(1, { random: rand }), BACKOFF_BASE_MS * 2);
  assertEquals(nextBackoffMs(2, { random: rand }), BACKOFF_BASE_MS * 4);
  assertEquals(
    nextBackoffMs(20, { random: rand }),
    BACKOFF_MAX_MS,
  );
});

Deno.test("nextBackoffMs applies jitter within ratio", () => {
  const low = nextBackoffMs(0, { random: () => 0 });
  const high = nextBackoffMs(0, { random: () => 1 });
  assertGreater(high, low);
  assertLessOrEqual(high, BACKOFF_BASE_MS * 1.2);
  assertGreater(low, BACKOFF_BASE_MS * 0.8 - 1);
});

Deno.test("parseWsMessage accepts valid snapshot", () => {
  const raw = JSON.stringify({
    type: "snapshot",
    ts: 1_700_000_000_000,
    system: null,
    runners: null,
    runs: null,
    vigil: {
      enabled: true,
      findingsTotal: 3,
      criticalCount: 1,
      highCount: 1,
      recentFindings: [{
        findingId: "f-1",
        severity: "critical",
        status: "new",
        description: "boom",
        timestamp: "2026-07-22T00:00:00Z",
        dataSource: "splunk",
      }],
    },
    errors: { system: "boom" },
  });
  const msg = parseWsMessage(raw);
  assertEquals(msg?.type, "snapshot");
  assertEquals(msg?.vigil?.enabled, true);
  assertEquals(msg?.vigil?.findingsTotal, 3);
  assertEquals(msg?.vigil?.recentFindings?.[0]?.findingId, "f-1");
  assertEquals(msg?.errors?.system, "boom");
});

Deno.test("parseWsMessage accepts vigil stub enabled-only", () => {
  const msg = parseWsMessage(JSON.stringify({
    type: "snapshot",
    ts: 1,
    system: null,
    runners: null,
    runs: null,
    vigil: { enabled: true },
  }));
  assertEquals(msg?.vigil, { enabled: true });
});

Deno.test("parseWsMessage rejects garbage", () => {
  assertEquals(parseWsMessage(""), null);
  assertEquals(parseWsMessage("{"), null);
  assertEquals(parseWsMessage(JSON.stringify({ type: "ping" })), null);
  assertEquals(
    parseWsMessage(JSON.stringify({ type: "snapshot", ts: "nope" })),
    null,
  );
});
