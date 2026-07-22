import { Sparkline } from "./Sparkline.tsx";

export interface StatMeterProps {
  label: string;
  /** Primary readout (e.g. "4.2 GB" or "1.24"). */
  value: string;
  /** 0-100 fill for the bar; omit for value-only metrics (uptime, load). */
  percent?: number | null;
  hint?: string;
  /** Bar color hint when utilization is high. */
  warnAt?: number;
  /** Optional recent values for an inline sparkline (≥2 points). */
  series?: number[] | null;
  class?: string;
}

function clampPercent(n: number): number {
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, n));
}

export function StatMeter(props: StatMeterProps) {
  const hasBar = props.percent != null && Number.isFinite(props.percent);
  const pct = hasBar ? clampPercent(props.percent!) : null;
  const warnAt = props.warnAt ?? 85;
  const hot = pct != null && pct >= warnAt;
  const series = props.series?.filter((v) => Number.isFinite(v)) ?? [];
  const showSpark = series.length >= 2;

  return (
    <div class={`min-w-0 ${props.class ?? ""}`.trim()}>
      <div class="flex items-baseline justify-between gap-2">
        <span class="text-xs font-medium tracking-wide text-muted uppercase">
          {props.label}
        </span>
        <span class="font-mono text-sm font-medium tabular-nums text-fg-strong">
          {props.value}
        </span>
      </div>
      {showSpark && (
        <div class="mt-1.5 text-accent-muted">
          <Sparkline values={series} label={`${props.label} trend`} />
        </div>
      )}
      {pct != null && (
        <div
          class="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-4/90"
          role="meter"
          aria-label={props.label}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(pct)}
        >
          <div
            class={`h-full rounded-full ${
              hot ? "bg-status-warning" : "bg-accent-muted"
            } motion-safe:transition-[width]`}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}
      {props.hint && (
        <p class="mt-1.5 font-mono text-[0.7rem] text-subtle">{props.hint}</p>
      )}
    </div>
  );
}
