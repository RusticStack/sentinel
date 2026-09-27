<script setup lang="ts">
import type { JobTimestamps } from "~~/shared/types/api";

// A job's phases from its timestamps — waiting, preparing, running,
// finalizing — as a bar scaled to the run's longest job, with the numbers
// spelled out. A phase never reached is absent.
const props = defineProps<{ t: JobTimestamps; scale: number; now: number }>();

const phases = computed(() => phasesOf(props.t, props.now));
const COLORS: Record<string, string> = { wait: "bg-(--ui-text-dimmed)", prep: "bg-warning", run: "bg-info", fin: "bg-success" };
const summary = computed(() => phases.value.map((p) => `${p.label} ${fmtMs(p.ms)}`).join(" · ") || "not started");
</script>

<script lang="ts">
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
</script>

<template>
  <div class="min-w-40">
    <div class="flex h-2 rounded-sm overflow-hidden bg-elevated" role="img" :aria-label="summary">
      <span v-for="p in phases" :key="p.key" :class="COLORS[p.key]" :style="{ width: `${Math.max(0.5, (100 * p.ms) / scale).toFixed(2)}%` }" />
    </div>
    <p class="text-xs text-muted mt-1">{{ summary }}</p>
  </div>
</template>
