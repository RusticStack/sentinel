// Formatting shared by every view. Unmeasured values show as an em dash,
// never as zero.

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = Number(n), u = 0;
  while (Math.abs(v) >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  return `${u ? v.toFixed(v < 10 ? 1 : 0) : v} ${units[u]}`;
}

export function fmtMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)} s`;
  const m = Math.floor(s / 60), r = Math.round(s % 60);
  if (m < 60) return `${m} min ${r} s`;
  return `${Math.floor(m / 60)} h ${m % 60} min`;
}

export const fmtNs = (ns: number | null | undefined) => (ns === null || ns === undefined ? "—" : fmtMs(ns / 1e6));

export function fmtAgo(ms: number | null | undefined, now = Date.now()): string {
  if (!ms) return "—";
  const d = now - ms;
  if (d < 5e3) return "just now";
  if (d < 60e3) return `${Math.round(d / 1e3)} s ago`;
  if (d < 3600e3) return `${Math.round(d / 60e3)} min ago`;
  if (d < 86400e3) return `${Math.round(d / 3600e3)} h ago`;
  return new Date(ms).toLocaleDateString();
}

export const shortId = (id: string | null | undefined) => (id ? id.replace(/^([a-z]+_)(.{8}).*$/, "$1$2") : "—");
export const shortSha = (sha: string | null | undefined) => (sha ? sha.slice(0, 12) : "—");
export const shortRef = (ref: string | null | undefined) => (ref ? ref.replace(/^refs\/(heads|tags)\//, "") : "—");
export const cpu = (millis: number | null | undefined) =>
  millis === null || millis === undefined ? "—" : `${(millis / 1000).toFixed(millis % 1000 ? 1 : 0)} CPU`;
export const words = (s: string | null | undefined) => (s ? s.replace(/_/g, " ") : "—");

type BadgeColor = "success" | "error" | "warning" | "info" | "neutral" | "primary";

/// A state's colour and icon; the state is always also spelled out.
export function stateLook(state: string): { color: BadgeColor; icon: string } {
  switch (state) {
    case "passed": case "published": case "hit": case "online":
      return { color: "success", icon: "i-lucide-circle-check" };
    case "active":
      return { color: "info", icon: "i-lucide-radio" };
    case "failed": case "infra_failed": case "refused":
      return { color: "error", icon: "i-lucide-circle-x" };
    case "timed_out":
      return { color: "error", icon: "i-lucide-timer-off" };
    case "offline":
      return { color: "neutral", icon: "i-lucide-circle-power" };
    case "canceled": case "suspended":
      return { color: "warning", icon: "i-lucide-ban" };
    case "skipped": case "miss": case "draining":
      return { color: "warning", icon: "i-lucide-skip-forward" };
    case "running": case "preparing": case "finalizing": case "leased": case "offered":
      return { color: "info", icon: "i-lucide-loader-circle" };
    case "blocked":
      return { color: "neutral", icon: "i-lucide-git-merge" };
    default:
      return { color: "neutral", icon: "i-lucide-circle-dashed" };
  }
}

export const TERMINAL = new Set(["passed", "failed", "infra_failed", "timed_out", "canceled", "skipped"]);
