<script setup lang="ts">
import type { TenantStorage } from "~~/shared/types/api";

// A tenant's storage (R01): what it holds against its quota, the limits the
// platform set, and each repository's usage and narrower policy.
const props = defineProps<{ slug: string }>();
const api = useApi();
const act = useAct();
const { data, refresh } = await useAsyncData(`storage-${props.slug}`,
  () => api<TenantStorage>(`/api/v1/tenants/${props.slug}/storage`));
const editing = ref<string | null>(null);
const DAY = 86_400_000;
const total = computed(() => (data.value ? data.value.usage.object_bytes + data.value.usage.log_bytes : 0));
const quota = computed(() => data.value?.effective.tenant_quota_bytes ?? 0);

async function save(repo: string, body: Record<string, number | null>) {
  if (await act(`Storage policy of ${repo}`, () => api(`/api/v1/tenants/${props.slug}/repos/${encodeURIComponent(repo)}/storage`, { method: "PUT", body }))) {
    editing.value = null;
    await refresh();
  }
}
const columns = [
  { accessorKey: "name", header: "Repository" }, { id: "artifacts", header: "Artifacts" }, { id: "logs", header: "Logs" },
  { id: "quota", header: "Quota" }, { id: "retention", header: "Retention" }, { id: "actions", header: "Actions" },
];
</script>

<template>
  <section v-if="data" aria-labelledby="storage-h" class="space-y-3">
    <h2 id="storage-h" class="text-base font-semibold">Storage</h2>
    <div class="grid gap-3 sm:grid-cols-3">
      <UCard>
        <p class="text-sm text-muted">Stored</p>
        <p class="text-lg font-semibold">{{ fmtBytes(total) }}</p>
        <p class="text-xs text-muted">{{ fmtBytes(data.usage.object_bytes) }} objects · {{ fmtBytes(data.usage.log_bytes) }} logs</p>
        <div v-if="quota" class="mt-2" role="meter" :aria-valuenow="Math.min(100, Math.round((100 * total) / quota))" aria-valuemin="0" aria-valuemax="100" :aria-label="`${fmtBytes(total)} of ${fmtBytes(quota)} quota used`">
          <div class="h-2 rounded bg-elevated overflow-hidden"><div class="h-full bg-primary" :style="{ width: `${Math.min(100, (100 * total) / quota)}%` }" /></div>
          <p class="text-xs text-muted mt-1">{{ Math.round((100 * total) / quota) }}% of {{ fmtBytes(quota) }}</p>
        </div>
        <p v-else class="text-xs text-muted mt-2">No quota</p>
      </UCard>
      <UCard>
        <p class="text-sm text-muted">Logs kept</p>
        <p class="text-lg font-semibold">{{ Math.round(data.effective.log_retention_ms / DAY * 10) / 10 }} days</p>
        <p class="text-xs text-muted">after the attempt finishes</p>
      </UCard>
      <UCard>
        <p class="text-sm text-muted">Artifacts kept at most</p>
        <p class="text-lg font-semibold">{{ Math.round(data.effective.artifact_retention_ms / DAY * 10) / 10 }} days</p>
        <p class="text-xs text-muted">a pipeline's <code>retain</code> is shortened to this</p>
      </UCard>
    </div>
    <p class="text-sm text-muted">The platform sets the tenant's limits. Each repository can have its own quota and shorter retention.</p>
    <UTable :data="data.repos" :columns="columns" caption="Repository storage" class="rounded-lg border border-default">
      <template #artifacts-cell="{ row }">{{ fmtBytes(row.original.usage.artifact_bytes) }}</template>
      <template #logs-cell="{ row }">{{ fmtBytes(row.original.usage.log_bytes) }}</template>
      <template #quota-cell="{ row }">{{ row.original.effective.repo_quota_bytes ? fmtBytes(row.original.effective.repo_quota_bytes) : "tenant's" }}</template>
      <template #retention-cell="{ row }">
        logs {{ Math.round(row.original.effective.log_retention_ms / DAY * 10) / 10 }}d · artifacts {{ Math.round(row.original.effective.artifact_retention_ms / DAY * 10) / 10 }}d
      </template>
      <template #actions-cell="{ row }">
        <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-sliders-horizontal" :aria-label="`Storage policy of ${row.original.name}`" @click="editing = row.original.name">Policy</UButton>
      </template>
    </UTable>
    <UModal :open="!!editing" :title="`Storage policy · ${editing}`" description="Blank fields inherit the tenant's limits." @update:open="(o) => !o && (editing = null)">
      <template #body>
        <StoragePolicyForm v-if="editing" :id="`repo-${editing}`"
          :policy="data.repos.find((r) => r.name === editing)!.policy"
          :inherited="{ quota_bytes: 0, log_retention_ms: data.effective.log_retention_ms, artifact_retention_ms: data.effective.artifact_retention_ms }"
          :max-log-days="data.effective.log_retention_ms / DAY" :max-artifact-days="data.effective.artifact_retention_ms / DAY"
          @save="(body) => save(editing!, body)" />
      </template>
    </UModal>
  </section>
</template>
