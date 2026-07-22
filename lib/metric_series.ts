/** Pure metric history helpers (safe for islands; no Deno KV). */

/** ~1h at the 15s realtime cadence. */
export const METRIC_HISTORY_MAX_SAMPLES = 240;
/** Skip writes closer than this (API + WS may both collect). */
export const METRIC_HISTORY_MIN_INTERVAL_MS = 12_000;
export const METRIC_HISTORY_MAX_AGE_MS = 60 * 60 * 1000;

export type MetricSample = {
  t: number;
  load1: number | null;
  memPct: number | null;
  diskPct: number | null;
};

export type MetricHistoryRecord = {
  samples: MetricSample[];
};

/**
 * Append a sample, drop stale points, and cap length.
 * Pure: safe for unit tests without KV.
 */
export function appendMetricSample(
  samples: MetricSample[],
  sample: MetricSample,
  opts?: {
    maxSamples?: number;
    minIntervalMs?: number;
    maxAgeMs?: number;
    now?: number;
  },
): MetricSample[] {
  const maxSamples = opts?.maxSamples ?? METRIC_HISTORY_MAX_SAMPLES;
  const minIntervalMs = opts?.minIntervalMs ?? METRIC_HISTORY_MIN_INTERVAL_MS;
  const maxAgeMs = opts?.maxAgeMs ?? METRIC_HISTORY_MAX_AGE_MS;
  const now = opts?.now ?? sample.t;

  const last = samples[samples.length - 1];
  if (last && sample.t - last.t < minIntervalMs) {
    return trimMetricSamples(samples, { maxSamples, maxAgeMs, now });
  }

  return trimMetricSamples([...samples, sample], {
    maxSamples,
    maxAgeMs,
    now,
  });
}

export function trimMetricSamples(
  samples: MetricSample[],
  opts?: {
    maxSamples?: number;
    maxAgeMs?: number;
    now?: number;
  },
): MetricSample[] {
  const maxSamples = opts?.maxSamples ?? METRIC_HISTORY_MAX_SAMPLES;
  const maxAgeMs = opts?.maxAgeMs ?? METRIC_HISTORY_MAX_AGE_MS;
  const now = opts?.now ?? Date.now();
  const cutoff = now - maxAgeMs;

  let next = samples.filter((s) => s.t >= cutoff);
  if (next.length > maxSamples) {
    next = next.slice(next.length - maxSamples);
  }
  return next;
}

export function seriesValues(
  samples: MetricSample[],
  key: "load1" | "memPct" | "diskPct",
): number[] {
  const out: number[] = [];
  for (const s of samples) {
    const v = s[key];
    if (v != null && Number.isFinite(v)) out.push(v);
  }
  return out;
}
