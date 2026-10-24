<script setup lang="ts">
const api = useApi();
const before = ref<number | null>(null);
const { data } = await useAsyncData(() => `platform-audit-${before.value}`,
  () => api<{ events: any[]; next: number | null }>(`/api/v1/admin/audit?limit=50${before.value ? `&before=${before.value}` : ""}`), { watch: [before] });
const columns = [{ accessorKey: "at_ms", header: "When" }, { accessorKey: "event", header: "Event" }, { accessorKey: "actor", header: "Actor" }, { accessorKey: "subject", header: "Subject" }, { accessorKey: "detail", header: "Detail" }];
</script>

<template>
  <section aria-labelledby="paudit-h" class="space-y-3">
    <h2 id="paudit-h" class="text-base font-semibold">Authentication and administration audit</h2>
    <UTable :data="data?.events ?? []" :columns="columns" caption="Audit" class="rounded-lg border border-default">
      <template #at_ms-cell="{ row }"><RelTime :ms="row.original.at_ms" /></template>
      <template #event-cell="{ row }">{{ words(row.original.event.replace(/-/g, "_")) }}</template>
      <template #actor-cell="{ row }"><code class="text-xs">{{ row.original.host_local ? "host" : shortId(row.original.actor) }}</code></template>
      <template #subject-cell="{ row }"><code class="text-xs">{{ shortId(row.original.subject) }}</code></template>
      <template #detail-cell="{ row }">{{ row.original.detail ?? "" }}</template>
    </UTable>
    <div class="flex gap-2">
      <UButton v-if="before" color="neutral" variant="outline" label="Newest" @click="before = null" />
      <UButton v-if="data?.next" color="neutral" variant="outline" label="Older" trailing-icon="i-lucide-arrow-right" @click="before = data!.next" />
    </div>
  </section>
</template>
