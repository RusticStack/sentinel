import { assertEquals } from "@std/assert";
import { setAppKvForTests } from "./kv.ts";
import {
  appendMetricSample,
  type MetricSample,
  recordMetricSample,
  sampleFromMetrics,
  seriesValues,
  trimMetricSamples,
} from "./metric_history.ts";
import type { SystemMetrics } from "./system.ts";

function sample(
  t: number,
  partial?: Partial<Omit<MetricSample, "t">>,
): MetricSample {
  return {
    t,
    load1: partial && "load1" in partial ? partial.load1! : 0.5,
    memPct: partial && "memPct" in partial ? partial.memPct! : 40,
    diskPct: partial && "diskPct" in partial ? partial.diskPct! : 20,
  };
}

function metricsFixture(
  overrides?: Partial<SystemMetrics>,
): SystemMetrics {
  return {
    platform: "linux",
    available: true,
    memory: { totalMb: 1000, usedMb: 400, availableMb: 600 },
    disk: {
      filesystem: "/dev/sda1",
      size: "50G",
      used: "10G",
      available: "40G",
      usePercent: 22,
      mount: "/",
    },
    load: { load1: 0.25, load5: 0.2, load15: 0.1 },
    uptime: "up 1 day",
    cpu: { cores: 4, model: "test" },
    expectedRunners: 4,
    ...overrides,
  };
}

Deno.test("appendMetricSample appends and caps length", () => {
  let samples: MetricSample[] = [];
  for (let i = 0; i < 5; i++) {
    samples = appendMetricSample(samples, sample(i * 15_000), {
      maxSamples: 3,
      minIntervalMs: 0,
      maxAgeMs: 1_000_000,
      now: i * 15_000,
    });
  }
  assertEquals(samples.length, 3);
  assertEquals(samples[0]!.t, 30_000);
  assertEquals(samples[2]!.t, 60_000);
});

Deno.test("appendMetricSample rate-limits close samples", () => {
  const first = sample(1_000);
  let samples = appendMetricSample([], first, {
    minIntervalMs: 12_000,
    maxAgeMs: 1_000_000,
  });
  samples = appendMetricSample(samples, sample(5_000), {
    minIntervalMs: 12_000,
    maxAgeMs: 1_000_000,
  });
  assertEquals(samples.length, 1);
  assertEquals(samples[0]!.t, 1_000);

  samples = appendMetricSample(samples, sample(14_000), {
    minIntervalMs: 12_000,
    maxAgeMs: 1_000_000,
  });
  assertEquals(samples.length, 2);
});

Deno.test("trimMetricSamples drops points older than max age", () => {
  const samples = [
    sample(0),
    sample(10_000),
    sample(50_000),
  ];
  const trimmed = trimMetricSamples(samples, {
    maxAgeMs: 30_000,
    maxSamples: 240,
    now: 50_000,
  });
  assertEquals(trimmed.map((s) => s.t), [50_000]);
});

Deno.test("seriesValues extracts finite points for a key", () => {
  const samples = [
    sample(1, { load1: 0.1, memPct: null }),
    sample(2, { load1: null, memPct: 55 }),
    sample(3, { load1: 0.3, memPct: 60 }),
  ];
  assertEquals(seriesValues(samples, "load1"), [0.1, 0.3]);
  assertEquals(seriesValues(samples, "memPct"), [55, 60]);
});

Deno.test("sampleFromMetrics maps host metrics to a sample", () => {
  const s = sampleFromMetrics(metricsFixture(), 99);
  assertEquals(s, {
    t: 99,
    load1: 0.25,
    memPct: 40,
    diskPct: 22,
  });
  assertEquals(sampleFromMetrics(metricsFixture({ available: false })), null);
});

Deno.test("recordMetricSample writes and reads via KV", async () => {
  const kv = await Deno.openKv(":memory:");
  setAppKvForTests(kv);
  try {
    const m = metricsFixture();
    const first = await recordMetricSample(m, 100_000);
    assertEquals(first.length, 1);
    assertEquals(first[0]!.memPct, 40);

    const skipped = await recordMetricSample(m, 105_000);
    assertEquals(skipped.length, 1);

    const second = await recordMetricSample(m, 120_000);
    assertEquals(second.length, 2);
    assertEquals(second[1]!.t, 120_000);
  } finally {
    setAppKvForTests(null);
    kv.close();
  }
});
