<script setup lang="ts">
import type { Explanation, LogPage, Run, Steps } from "~~/shared/types/api";

// One attempt's log: steps that fold, windowed lines, search, deep links,
// and live following through the log stream.
const route = useRoute();
const api = useApi();
const session = useSession();
const runId = route.params.id as string;
const attempt = route.params.attempt as string;

const { data } = await useAsyncData(`log-${attempt}`, async () => {
  const [run, explain, steps, first] = await Promise.all([
    api<Run>(`/api/v1/runs/${runId}`),
    api<Explanation>(`/api/v1/runs/${runId}/pipeline`).catch(() => null),
    api<Steps>(`/api/v1/attempts/${attempt}/steps`).catch(() => ({ attempt, present: false } as Steps)),
    // One frame is enough to learn whether retention removed the log.
    api<LogPage>(`/api/v1/attempts/${attempt}/logs?limit=1`).catch(() => null),
  ]);
  return { run, explain, steps, expired: first?.expired_ms ?? null };
});
const job = computed(() => data.value?.run.jobs.find((j) => j.attempt === attempt) ?? null);
const stepList = computed(() => {
  const spec = data.value?.explain && job.value ? data.value.explain.jobs.find((j) => j.name === job.value!.name) : null;
  if (spec) return spec.steps.map((s, index) => ({ index, id: s.id }));
  if (data.value?.steps.present) return data.value.steps.steps!.map((s) => ({ index: s.index, id: s.id }));
  return [{ index: 0, id: "step 0" }];
});
// The current attempt's log is live until its end marker is durable; an
// earlier attempt's is finished.
const complete = computed(() => !job.value || job.value.log_state === "complete" || (job.value.terminal && job.value.log_state === "incomplete"));
const refused = ref<string | null>(null);
async function onRefused(message: string) {
  refused.value = message;
  await session.refreshTenants();
}
useHead({ title: () => `Log · ${job.value?.name ?? shortId(attempt)} · Sentinel` });
</script>

<template>
  <SPage id="log" :title="`Log · ${job?.name ?? shortId(attempt)}`">
    <template #actions>
      <StateBadge v-if="job" :state="job.state" />
    </template>
    <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted">
      <ULink :to="`/runs/${runId}`" class="text-primary underline">Run {{ shortId(runId) }}</ULink>
      <span>attempt <code>{{ shortId(attempt) }}</code></span>
      <span v-if="job && job.attempt !== attempt">an earlier attempt</span>
      <span v-if="data?.steps.present && data.steps.timings_ns">
        {{ Object.entries(data.steps.timings_ns).map(([k, v]) => `${words(k)} ${fmtNs(v)}`).join(" · ") }}
      </span>
    </div>
    <UAlert v-if="refused" color="error" variant="subtle" icon="i-lucide-lock" :title="refused" role="alert" :actions="[{ label: 'Back to your tenants', to: '/' }]" />
    <UAlert v-if="data?.expired" color="neutral" variant="subtle" icon="i-lucide-archive-x" role="status"
      title="This log was removed by retention"
      :description="`Its storage policy kept it until ${new Date(data.expired).toUTCString()}. The run's result, its steps and their timings are still here.`" />
    <ClientOnly v-else>
      <LogPane :attempt="attempt" :run="runId" :steps="stepList" :outcomes="data?.steps.present ? data.steps.steps! : null" :complete="complete" @refused="onRefused" />
      <template #fallback><USkeleton class="h-[70vh] w-full" /></template>
    </ClientOnly>
  </SPage>
</template>
