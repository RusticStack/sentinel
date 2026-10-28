import type { JobTimestamps } from "../../lib/types";
import { fmtMs } from "../../lib/format.ts";

export function phasesOf(t: JobTimestamps, now: number) {
  const end = t.terminal_ms ?? now;
  const out: { key: string; label: string; ms: number }[] = [];
  const add = (key: string, label: string, from: number | null, to: number | null) => {
    if (from !== null && to !== null && to >= from) out.push({ key, label, ms: to - from });
  };
  add("wait", "waiting", t.queued_ms, t.leased_ms ?? end);
  add("prep", "preparing", t.leased_ms, t.running_ms ?? t.finalizing_ms ?? end);
  add("run", "running", t.running_ms, t.finalizing_ms ?? end);
  add("fin", "finalizing", t.finalizing_ms, end);
  return out;
}

const COLORS: Record<string, string> = { wait: "bg-dimmed", prep: "bg-warning", run: "bg-info", fin: "bg-success" };

export function PhaseBar({ t, scale, now }: { t: JobTimestamps; scale: number; now: number }) {
  const phases = phasesOf(t, now);
  const summary = phases.map((p) => `${p.label} ${fmtMs(p.ms)}`).join(" · ") || "not started";
  return (
    <div className="min-w-40">
      <div className="flex h-2 overflow-hidden rounded-sm bg-elevated" role="img" aria-label={summary}>
        {phases.map((p) => <span key={p.key} className={COLORS[p.key]} style={{ width: `${Math.max(0.5, (100 * p.ms) / scale).toFixed(2)}%` }} />)}
      </div>
      <p className="mt-1 text-xs text-muted">{summary}</p>
    </div>
  );
}
