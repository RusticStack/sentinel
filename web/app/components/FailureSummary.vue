<script setup lang="ts">
import type { JobStatus } from "~~/shared/types/api";

// Why a job failed: the failed step, the first diagnostics with their
// evidence, and the output tail — each linking into the log at its frame.
// The same bounded failure view an agent reads (`/attempts/{id}/failure`).
const props = defineProps<{ job: JobStatus; run: string }>();
const api = useApi();
const { data: f, error } = await useAsyncData(`failure-${props.job.attempt}`, () =>
  api<any>(`/api/v1/attempts/${props.job.attempt}/failure?budget=6144&limit=10`), { lazy: true, server: false });

const diagnostics = computed(() => {
  const out: any[] = [];
  for (const r of f.value?.reports || []) for (const d of r.report?.diagnostics || []) out.push(d);
  return out;
});
const tail = computed(() => (f.value?.tail?.frames || []) as any[]);
const tailText = computed(() => tail.value.map((fr) => (fr.binary ? `[${fr.bytes} bytes of binary output]` : fr.text)).join("").replace(/\x1b\[[0-?]*[ -\/]*[@-~]/g, ""));
const logLink = (step: number, seq: number) => `/runs/${props.run}/logs/${props.job.attempt}?step=${step}&seq=${seq}`;
</script>

<template>
  <UCard :aria-label="`Failure of ${job.name}`" :ui="{ body: 'space-y-3' }">
    <template #header>
      <div class="flex items-center gap-2">
        <UIcon name="i-lucide-octagon-alert" class="text-error size-5" />
        <h2 class="font-semibold">Why {{ job.name }} {{ words(job.state) }}</h2>
      </div>
    </template>
    <p v-if="error" class="text-sm text-muted">Failure summary unavailable: {{ error.message }}</p>
    <USkeleton v-else-if="!f" class="h-16 w-full" />
    <template v-else>
      <p v-if="f.failed_step" class="text-sm">
        Failed step <strong>{{ f.failed_step.id }}</strong>
        ({{ words(f.failed_step.outcome) }}<template v-if="f.failed_step.exit_code != null">, exit {{ f.failed_step.exit_code }}</template><template v-if="f.failed_step.signal">, signal {{ f.failed_step.signal }}</template>)
      </p>
      <ul v-if="diagnostics.length" class="space-y-1.5 text-sm">
        <li v-for="(d, i) in diagnostics" :key="i" class="flex flex-wrap items-baseline gap-2">
          <UBadge :color="d.severity === 'warning' ? 'warning' : 'error'" variant="subtle" :label="d.severity" size="sm" />
          <code v-if="d.source" class="text-xs">{{ d.source.path }}<template v-if="d.source.line">:{{ d.source.line }}</template></code>
          <code v-else-if="d.test" class="text-xs">{{ d.test.name }}</code>
          <span class="break-words">{{ d.message.length > 400 ? d.message.slice(0, 400) + "…" : d.message }}</span>
          <ULink v-if="d.evidence?.[0]" :to="logLink(d.evidence[0].step_index, d.evidence[0].start.sequence)" class="text-primary underline">evidence</ULink>
        </li>
      </ul>
      <template v-if="tail.length">
        <h3 class="text-sm font-semibold">Output tail</h3>
        <pre class="text-xs font-mono bg-muted rounded-md p-2 max-h-72 overflow-auto whitespace-pre-wrap break-all">{{ tailText }}</pre>
        <ULink :to="logLink(tail[0].step, tail[0].sequence)" class="text-sm text-primary underline">Open this in the log</ULink>
      </template>
      <p v-if="f.truncated" class="text-xs text-muted">Summary cut to its budget; the full log has everything.</p>
      <p v-if="!f.log_complete" class="text-xs text-muted">The log is incomplete or still being written.</p>
      <p v-if="!f.failed_step && !diagnostics.length && !tail.length" class="text-sm">
        No diagnostics were found. <ULink :to="`/runs/${run}/logs/${job.attempt}`" class="text-primary underline">Open the log</ULink>
      </p>
    </template>
  </UCard>
</template>
