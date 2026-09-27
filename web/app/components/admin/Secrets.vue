<script setup lang="ts">
// Secret metadata only: names, versions, state and bindings. Values are
// write-only (`sentinel secrets set`) and never read back by anything.
const props = defineProps<{ slug: string }>();
const api = useApi();
const act = useAct();
const { data: repos } = await useRepos(() => props.slug);
const scope = ref("");
const scopes = computed(() => [{ label: "Tenant secrets", value: "" }, ...(repos.value?.repos ?? []).map((r) => ({ label: `Repository ${r.name}`, value: r.name }))]);
const { data, refresh } = await useAsyncData(
  () => `secrets-${props.slug}-${scope.value}`,
  async () => {
    const q = scope.value ? `?repo=${encodeURIComponent(scope.value)}&limit=100` : "?limit=100";
    const secrets = await api<{ secrets: any[] }>(`/api/v1/tenants/${props.slug}/secrets${q}`);
    const bindings = scope.value ? await api<{ bindings: any[] }>(`/api/v1/tenants/${props.slug}/secret-bindings?repo=${encodeURIComponent(scope.value)}&limit=100`) : null;
    return { secrets: secrets.secrets, bindings: bindings?.bindings ?? null };
  },
  { watch: [scope] },
);
const confirmDelete = ref<any | null>(null);
async function remove() {
  const s = confirmDelete.value;
  confirmDelete.value = null;
  const q = scope.value ? `?repo=${encodeURIComponent(scope.value)}` : "";
  if (await act(`Delete ${s.name}`, () => api(`/api/v1/tenants/${props.slug}/secrets/${encodeURIComponent(s.name)}${q}`, {
    method: "DELETE", headers: { "if-match": String(s.version), "idempotency-key": `ui-${crypto.randomUUID()}` },
  }))) await refresh();
}
const columns = [{ accessorKey: "name", header: "Name" }, { accessorKey: "version", header: "Version" }, { accessorKey: "active", header: "State" }, { accessorKey: "updated_ms", header: "Updated" }, { id: "actions", header: "Actions" }];
const bindingColumns = [{ accessorKey: "job", header: "Job" }, { accessorKey: "step", header: "Step" }, { accessorKey: "name", header: "Variable" }, { id: "source", header: "Source" }];
</script>

<template>
  <section aria-labelledby="secrets-h" class="space-y-3">
    <h2 id="secrets-h" class="text-base font-semibold">Secrets</h2>
    <p class="text-sm text-muted">Names, versions and where they apply. Values are write-only (<code>sentinel secrets set</code>) and never shown.</p>
    <UFormField label="Scope" name="scope" class="w-64"><USelect id="s-scope" v-model="scope" :items="scopes" class="w-full" /></UFormField>
    <UTable :data="data?.secrets ?? []" :columns="columns" caption="Secrets" empty="No secrets in this scope." class="rounded-lg border border-default">
      <template #name-cell="{ row }"><code class="text-xs">{{ row.original.name }}</code></template>
      <template #active-cell="{ row }"><StateBadge :state="row.original.active ? 'online' : 'canceled'" :label="row.original.active ? 'active' : 'revoked'" /></template>
      <template #updated_ms-cell="{ row }"><RelTime :ms="row.original.updated_ms" /></template>
      <template #actions-cell="{ row }">
        <UButton v-if="row.original.active" size="sm" color="error" variant="ghost" icon="i-lucide-trash-2" :aria-label="`Delete ${row.original.name}`" @click="confirmDelete = row.original">Delete</UButton>
      </template>
    </UTable>
    <template v-if="data?.bindings">
      <h3 class="text-sm font-semibold">Bindings</h3>
      <UTable :data="data.bindings" :columns="bindingColumns" caption="Bindings" empty="No bindings." class="rounded-lg border border-default">
        <template #job-cell="{ row }">{{ row.original.job || "any" }}</template>
        <template #step-cell="{ row }">{{ row.original.step || "any" }}</template>
        <template #name-cell="{ row }"><code class="text-xs">{{ row.original.name }}</code></template>
        <template #source-cell="{ row }">{{ row.original.override_tenant ? "overrides the tenant secret" : row.original.from_tenant ? "tenant secret" : "repository secret" }}</template>
      </UTable>
    </template>
  </section>
  <UModal :open="!!confirmDelete" :title="`Delete ${confirmDelete?.name}?`" description="Every version is revoked and the name is reserved." @update:open="(o) => !o && (confirmDelete = null)">
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="ghost" label="Keep" @click="confirmDelete = null" />
        <UButton color="error" label="Delete" @click="remove" />
      </div>
    </template>
  </UModal>
</template>
