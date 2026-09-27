<script setup lang="ts">
const props = defineProps<{ slug: string }>();
const api = useApi();
const before = ref<number | null>(null);
const { data } = await useAsyncData(() => `audit-${props.slug}-${before.value}`,
  () => api<{ events: any[]; next: number | null }>(`/api/v1/tenants/${props.slug}/audit?limit=50${before.value ? `&before=${before.value}` : ""}`), { watch: [before] });
const columns = [{ accessorKey: "at_ms", header: "When" }, { accessorKey: "action", header: "Action" }, { accessorKey: "target", header: "Target" }, { accessorKey: "actor", header: "Actor" }, { accessorKey: "via", header: "Via" }];
</script>

<template>
  <section aria-labelledby="audit-h" class="space-y-3">
    <h2 id="audit-h" class="text-base font-semibold">Run control audit</h2>
    <UTable :data="data?.events ?? []" :columns="columns" caption="Audit" empty="Nothing recorded yet." class="rounded-lg border border-default">
      <template #at_ms-cell="{ row }"><RelTime :ms="row.original.at_ms" /></template>
      <template #action-cell="{ row }">{{ words(row.original.action) }}</template>
      <template #target-cell="{ row }">
        <ULink v-if="row.original.target?.startsWith('run_')" :to="`/runs/${row.original.target}`" class="text-primary underline font-mono text-xs">{{ shortId(row.original.target) }}</ULink>
        <code v-else class="text-xs">{{ shortId(row.original.target) }}</code>
      </template>
      <template #actor-cell="{ row }"><code class="text-xs">{{ shortId(row.original.actor) }}</code></template>
      <template #via-cell="{ row }">{{ words(row.original.via) }}<template v-if="row.original.client"> ({{ row.original.client }})</template></template>
    </UTable>
    <div class="flex gap-2">
      <UButton v-if="before" color="neutral" variant="outline" label="Newest" @click="before = null" />
      <UButton v-if="data?.next" color="neutral" variant="outline" label="Older" trailing-icon="i-lucide-arrow-right" @click="before = data!.next" />
    </div>
  </section>
</template>
