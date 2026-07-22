import type { StatusTone } from "../components/StatusBadge.tsx";

/** Map GitHub workflow run status/conclusion to StatusBadge tones. */
export function workflowRunTone(
  status: string | null,
  conclusion: string | null,
): StatusTone {
  if (status === "queued" || status === "waiting" || status === "requested") {
    return "info";
  }
  if (status === "in_progress" || status === "pending") {
    return "busy";
  }
  switch (conclusion) {
    case "success":
      return "success";
    case "failure":
    case "timed_out":
    case "startup_failure":
      return "error";
    case "cancelled":
    case "skipped":
    case "neutral":
      return "idle";
    case "action_required":
      return "warning";
    default:
      return status === "completed" ? "idle" : "info";
  }
}

export function workflowRunLabel(
  status: string | null,
  conclusion: string | null,
): string {
  if (conclusion) return conclusion.replaceAll("_", " ");
  if (status) return status.replaceAll("_", " ");
  return "unknown";
}

/** Compact relative time for run tables (SSR-friendly, no Intl dependency). */
export function formatRelativeTime(
  iso: string,
  nowMs = Date.now(),
): string {
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return "-";
  const deltaSec = Math.round((nowMs - then) / 1000);
  const abs = Math.abs(deltaSec);
  const future = deltaSec < 0;
  const suffix = future ? "from now" : "ago";

  if (abs < 60) return future ? "soon" : "just now";
  if (abs < 3600) {
    const m = Math.round(abs / 60);
    return `${m}m ${suffix}`;
  }
  if (abs < 86400) {
    const h = Math.round(abs / 3600);
    return `${h}h ${suffix}`;
  }
  const d = Math.round(abs / 86400);
  return `${d}d ${suffix}`;
}

export function formatMemoryMb(usedMb: number, totalMb: number): string {
  const fmt = (mb: number) =>
    mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${Math.round(mb)} MB`;
  return `${fmt(usedMb)} / ${fmt(totalMb)}`;
}

export function memoryUsedPercent(usedMb: number, totalMb: number): number {
  if (!totalMb || totalMb <= 0) return 0;
  return (usedMb / totalMb) * 100;
}

export function shortSha(sha: string, len = 7): string {
  return sha.slice(0, len);
}

/** Map Vigil finding/case severity or priority to StatusBadge tones. */
export function severityTone(severity: string | null | undefined): StatusTone {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "error";
    case "high":
      return "warning";
    case "medium":
      return "busy";
    case "low":
      return "info";
    case "info":
    case "informational":
      return "idle";
    default:
      return "idle";
  }
}

export function caseStatusTone(status: string | null | undefined): StatusTone {
  switch ((status ?? "").toLowerCase()) {
    case "open":
    case "new":
    case "in_progress":
    case "investigating":
      return "busy";
    case "closed":
    case "resolved":
      return "success";
    case "escalated":
      return "error";
    default:
      return "idle";
  }
}
