<script setup lang="ts">
import type { RepoSync } from "~~/shared/types/api";

// How far GitHub feedback lags: per repository, check runs waiting to
// reach GitHub and the oldest one's age, refusals in the last 24 hours, the
// last accepted publication, and deliveries not yet turned into runs.
const route = useRoute();
const api = useApi();
const slug = route.params.slug as string;
useHead({ title: `GitHub sync · ${slug} · Sentinel` });

const { data, refresh } = await useAsyncData(`sync-${slug}`, () => api<{ now_ms: number; repos: RepoSync[]; next: string | null }>(`/api/v1/tenants/${slug}/sync?limit=100`));
usePolling(refresh, 10000);
const lag = (since: number | null) => (since && data.value ? data.value.now_ms - since : null);
const columns = [
  { accessorKey: "name", header: "Repository" }, { accessorKey: "pending", header: "Pending checks" }, { id: "oldest", header: "Oldest pending" },
  { accessorKey: "refused", header: "Refused (24 h)" }, { id: "published", header: "Last published" },
  { accessorKey: "open_deliveries", header: "Open deliveries" }, { id: "delivery", header: "Oldest delivery" },
];
</script>

<template>
  <SPage id="sync" :title="`GitHub sync · ${slug}`">
    <p class="text-sm text-muted">Refreshes every 10 s. A check pending for more than a minute is marked.</p>
    <UTable :data="data?.repos ?? []" :columns="columns" caption="Synchronization by repository" class="rounded-lg border border-default">
      <template #oldest-cell="{ row }">
        <UBadge v-if="lag(row.original.oldest_pending_ms) !== null" :color="lag(row.original.oldest_pending_ms)! > 60000 ? 'error' : 'neutral'" variant="subtle" :label="fmtMs(lag(row.original.oldest_pending_ms))" />
        <span v-else class="text-muted">—</span>
      </template>
      <template #refused-cell="{ row }">
        <UBadge v-if="row.original.refused" color="error" variant="subtle" :label="String(row.original.refused)" />
        <span v-else>0</span>
      </template>
      <template #published-cell="{ row }"><RelTime :ms="row.original.last_published_ms" /></template>
      <template #delivery-cell="{ row }">{{ row.original.oldest_delivery_ms ? fmtMs(lag(row.original.oldest_delivery_ms)) : "—" }}</template>
    </UTable>
    <p v-if="data?.next" class="text-sm text-muted">Only the first 100 repositories are shown.</p>
  </SPage>
</template>
