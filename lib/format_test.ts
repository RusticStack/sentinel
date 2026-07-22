import { assertEquals } from "@std/assert";
import {
  caseStatusTone,
  formatMemoryMb,
  formatRelativeTime,
  memoryUsedPercent,
  severityTone,
  shortSha,
  workflowRunLabel,
  workflowRunTone,
} from "./format.ts";

Deno.test("workflowRunTone maps conclusions and in-progress", () => {
  assertEquals(workflowRunTone("completed", "success"), "success");
  assertEquals(workflowRunTone("completed", "failure"), "error");
  assertEquals(workflowRunTone("in_progress", null), "busy");
  assertEquals(workflowRunTone("queued", null), "info");
});

Deno.test("workflowRunLabel prefers conclusion", () => {
  assertEquals(workflowRunLabel("completed", "timed_out"), "timed out");
  assertEquals(workflowRunLabel("in_progress", null), "in progress");
});

Deno.test("formatRelativeTime buckets", () => {
  const now = Date.parse("2026-07-22T12:00:00Z");
  assertEquals(
    formatRelativeTime("2026-07-22T11:59:50Z", now),
    "just now",
  );
  assertEquals(
    formatRelativeTime("2026-07-22T11:30:00Z", now),
    "30m ago",
  );
  assertEquals(
    formatRelativeTime("2026-07-22T09:00:00Z", now),
    "3h ago",
  );
});

Deno.test("memory helpers", () => {
  assertEquals(formatMemoryMb(512, 2048), "512 MB / 2.0 GB");
  assertEquals(memoryUsedPercent(512, 2048), 25);
  assertEquals(shortSha("abcdef0123456789"), "abcdef0");
});

Deno.test("severityTone and caseStatusTone", () => {
  assertEquals(severityTone("critical"), "error");
  assertEquals(severityTone("high"), "warning");
  assertEquals(severityTone("medium"), "busy");
  assertEquals(severityTone(null), "idle");
  assertEquals(caseStatusTone("open"), "busy");
  assertEquals(caseStatusTone("resolved"), "success");
});
