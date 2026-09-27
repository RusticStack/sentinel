<script setup lang="ts">
import type { Explanation, JobStatus } from "~~/shared/types/api";

// The run's jobs as a graph: a job sits one column right of its deepest
// dependency, in compiled order within a column. Each node links to its
// log; the jobs table below carries the same facts for anyone not reading
// the picture.
const props = defineProps<{ explain: Explanation; jobs: JobStatus[]; run: string }>();
const W = 176, H = 42, GX = 56, GY = 14, PAD = 12;

const layout = computed(() => {
  const level = new Map<string, number>();
  for (const job of props.explain.jobs) {
    level.set(job.name, job.needs.length ? 1 + Math.max(...job.needs.map((n) => level.get(n) ?? 0)) : 0);
  }
  const columns: string[][] = [];
  for (const job of props.explain.jobs) (columns[level.get(job.name)!] ||= []).push(job.name);
  const pos = new Map<string, [number, number]>();
  columns.forEach((col, x) => col.forEach((name, y) => pos.set(name, [PAD + x * (W + GX), PAD + y * (H + GY)])));
  const width = PAD * 2 + columns.length * (W + GX) - GX;
  const height = PAD * 2 + Math.max(1, ...columns.map((c) => c.length)) * (H + GY) - GY;
  const edges = props.explain.jobs.flatMap((job) => job.needs.map((need) => {
    const [x1, y1] = pos.get(need)!, [x2, y2] = pos.get(job.name)!;
    const a = [x1 + W, y1 + H / 2], b = [x2, y2 + H / 2];
    return `M${a[0]},${a[1]} C${a[0]! + GX / 2},${a[1]} ${b[0]! - GX / 2},${b[1]} ${b[0]},${b[1]}`;
  }));
  return { pos, width, height, edges };
});

const byName = computed(() => new Map(props.jobs.map((j) => [j.name, j])));
const colorOf = (state: string) => `text-${stateLook(state).color === "neutral" ? "muted" : stateLook(state).color}`;
const label = computed(() => `Job graph: ${props.explain.jobs.map((j) => `${j.name}${j.needs.length ? " after " + j.needs.join(" and ") : ""}`).join("; ")}`);
</script>

<template>
  <div class="dag overflow-x-auto rounded-lg border border-default bg-muted">
    <svg :width="layout.width" :height="layout.height" :viewBox="`0 0 ${layout.width} ${layout.height}`" role="group" :aria-label="label">
      <path v-for="(d, i) in layout.edges" :key="i" class="edge" :d="d" />
      <template v-for="job in explain.jobs" :key="job.name">
        <component
          :is="byName.get(job.name)?.attempt ? 'a' : 'g'"
          v-bind="byName.get(job.name)?.attempt ? { href: `/runs/${run}/logs/${byName.get(job.name)!.attempt}`, 'aria-label': `${job.name}: ${words(byName.get(job.name)!.state)}, open log` } : {}"
          @click="(e: MouseEvent) => { const a = byName.get(job.name)?.attempt; if (a) { e.preventDefault(); navigateTo(`/runs/${run}/logs/${a}`) } }"
        >
          <g :class="['node', colorOf(byName.get(job.name)?.state ?? 'pending')]" :transform="`translate(${layout.pos.get(job.name)![0]},${layout.pos.get(job.name)![1]})`">
            <rect :width="W" :height="H" rx="8" />
            <text x="10" y="17">{{ job.name.length > 22 ? job.name.slice(0, 21) + "…" : job.name }}</text>
            <text x="10" y="33" class="state">{{ words(byName.get(job.name)?.state ?? "pending") }}</text>
          </g>
        </component>
      </template>
    </svg>
  </div>
</template>
