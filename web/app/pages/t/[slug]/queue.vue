<script setup lang="ts">
// Why waiting jobs wait: the scheduler's reason for each, oldest first,
// with the missing quantities spelled out.
const route = useRoute();
const api = useApi();
const slug = route.params.slug as string;
useHead({ title: `Queue · ${slug} · Sentinel` });

const REASONS: Record<string, string> = {
  dependency: "waiting for jobs it needs",
  policy: "held by policy",
  no_matching_worker: "no worker is large enough",
  disk_short: "no worker has the scratch space",
  worker_offline: "matching workers are offline",
  capacity: "matching workers are busy",
  arch_mismatch: "no worker has this architecture",
  label_missing: "no worker has the required labels",
  drain: "matching workers are draining",
  concurrency_limit: "its concurrency group is full",
  fairness_hold: "held for fairness to other work",
  locality_wait: "waiting for a worker with warm caches",
  ready: "ready: the next placement pass takes it",
};
function explain(r: any) {
  const parts = [REASONS[r.code] ?? words(r.code)];
  if (r.detail) parts.push(`(${r.detail})`);
  if (r.cpu_short) parts.push(`— short ${cpu(r.cpu_short)}`);
  if (r.memory_short) parts.push(`— short ${fmtBytes(r.memory_short)} memory`);
  if (r.disk_short) parts.push(`— short ${fmtBytes(r.disk_short)} disk`);
  return parts.join(" ");
}

const { data: repos } = await useRepos(slug);
const names = computed(() => new Map((repos.value?.repos ?? []).map((r) => [r.id, r.name])));
const { data: queue, refresh } = await useAsyncData(`queue-${slug}`, () => api<{ jobs: any[]; total: number; truncated: boolean }>(`/api/v1/queue?tenant=${slug}&limit=200`));
usePolling(refresh, 5000);

const columns = [
  { accessorKey: "job", header: "Job" }, { accessorKey: "run", header: "Run" }, { accessorKey: "repo", header: "Repository" },
  { accessorKey: "age_ms", header: "Waiting" }, { id: "reason", header: "Reason" },
];
</script>

<template>
  <SPage id="queue" :title="`Queue · ${slug}`">
    <p class="text-sm text-muted">
      {{ queue?.total ?? 0 }} waiting job{{ queue?.total === 1 ? "" : "s" }}<template v-if="queue?.truncated">; the oldest {{ queue.jobs.length }} are shown</template>.
      Refreshes every 5 s.
    </p>
    <UTable :data="queue?.jobs ?? []" :columns="columns" caption="Waiting jobs" empty="Nothing is waiting." class="rounded-lg border border-default">
      <template #job-cell="{ row }"><code class="text-xs">{{ shortId(row.original.job) }}</code></template>
      <template #run-cell="{ row }"><ULink :to="`/runs/${row.original.run}`" class="text-primary underline">{{ shortId(row.original.run) }}</ULink></template>
      <template #repo-cell="{ row }">{{ names.get(row.original.repo) ?? shortId(row.original.repo) }}</template>
      <template #age_ms-cell="{ row }">{{ fmtMs(row.original.age_ms) }}</template>
      <template #reason-cell="{ row }">
        <div class="flex flex-wrap items-center gap-2">
          <UBadge :color="row.original.reason.code === 'ready' ? 'info' : 'warning'" variant="subtle" :label="words(row.original.reason.code)" />
          <span>{{ explain(row.original.reason) }}</span>
        </div>
      </template>
    </UTable>
  </SPage>
</template>
