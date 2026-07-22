/**
 * Host metric history in Deno KV (same DB as sessions).
 * Key: ["metrics", "host"] → { samples: MetricSample[] } (ring buffer, ~1h).
 */
import { memoryUsedPercent } from "./format.ts";
import { getAppKv } from "./kv.ts";
import {
  appendMetricSample,
  type MetricHistoryRecord,
  type MetricSample,
  trimMetricSamples,
} from "./metric_series.ts";
import type { SystemMetrics } from "./system.ts";

export {
  appendMetricSample,
  METRIC_HISTORY_MAX_AGE_MS,
  METRIC_HISTORY_MAX_SAMPLES,
  METRIC_HISTORY_MIN_INTERVAL_MS,
  type MetricHistoryRecord,
  type MetricSample,
  seriesValues,
  trimMetricSamples,
} from "./metric_series.ts";

const HISTORY_KEY: Deno.KvKey = ["metrics", "host"];

export function sampleFromMetrics(
  metrics: SystemMetrics,
  t = Date.now(),
): MetricSample | null {
  if (!metrics.available) return null;

  const load1 = metrics.load != null && Number.isFinite(metrics.load.load1)
    ? metrics.load.load1
    : null;
  const memPct = metrics.memory
    ? memoryUsedPercent(metrics.memory.usedMb, metrics.memory.totalMb)
    : null;
  const diskPct = metrics.disk != null &&
      Number.isFinite(metrics.disk.usePercent)
    ? metrics.disk.usePercent
    : null;

  if (load1 == null && memPct == null && diskPct == null) return null;

  return {
    t,
    load1,
    memPct: memPct != null && Number.isFinite(memPct) ? memPct : null,
    diskPct,
  };
}

export async function readMetricHistory(): Promise<MetricSample[]> {
  const kv = await getAppKv();
  const entry = await kv.get<MetricHistoryRecord>(HISTORY_KEY);
  const samples = entry.value?.samples ?? [];
  return trimMetricSamples(samples);
}

/**
 * Record a sample when due, then return the capped history.
 * No-ops (still returns history) when metrics cannot form a sample.
 */
export async function recordMetricSample(
  metrics: SystemMetrics,
  now = Date.now(),
): Promise<MetricSample[]> {
  const sample = sampleFromMetrics(metrics, now);
  const kv = await getAppKv();
  const entry = await kv.get<MetricHistoryRecord>(HISTORY_KEY);
  const current = entry.value?.samples ?? [];

  if (!sample) {
    return trimMetricSamples(current, { now });
  }

  const next = appendMetricSample(current, sample, { now });
  const lastBefore = current[current.length - 1];
  const lastAfter = next[next.length - 1];
  const added = lastAfter != null &&
    (lastBefore == null || lastAfter.t !== lastBefore.t);
  const trimmed = next.length < current.length;

  if (added || trimmed) {
    await kv.set(HISTORY_KEY, { samples: next } satisfies MetricHistoryRecord);
  }
  return next;
}
