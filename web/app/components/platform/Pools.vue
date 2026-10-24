<script setup lang="ts">
const api = useApi();
const act = useAct();
const { data, refresh } = await useAsyncData("platform-pools", () => api<{ pools: any[] }>("/api/v1/admin/pools"));
const form = reactive({ name: "", kind: "shared", tenant: "" });
const grantTo = reactive<Record<string, string>>({});
async function create() {
  const body: any = { name: form.name, kind: form.kind };
  if (form.kind === "dedicated") body.tenant = form.tenant;
  if (await act(`Create ${form.name}`, () => api("/api/v1/admin/pools", { method: "POST", body }))) { form.name = ""; await refresh(); }
}
async function grant(p: any, slug: string, on: boolean) {
  if (await act(`${on ? "Grant" : "Revoke"} ${p.name} ${on ? "to" : "from"} ${slug}`, () => api(`/api/v1/admin/pools/${p.id}/grants/${encodeURIComponent(slug)}`, { method: on ? "PUT" : "DELETE" }))) {
    grantTo[p.id] = "";
    await refresh();
  }
}
const columns = [{ accessorKey: "name", header: "Pool" }, { accessorKey: "kind", header: "Kind" }, { accessorKey: "workers", header: "Workers" }, { id: "tenants", header: "Tenants" }, { id: "grant", header: "Grant" }];
</script>

<template>
  <section aria-labelledby="pools-h" class="space-y-3">
    <h2 id="pools-h" class="text-base font-semibold">Worker pools</h2>
    <UTable :data="data?.pools ?? []" :columns="columns" caption="Pools" class="rounded-lg border border-default">
      <template #name-cell="{ row }"><span class="font-medium">{{ row.original.name }}</span><UBadge v-if="!row.original.active" color="warning" variant="subtle" label="inactive" class="ml-2" /></template>
      <template #tenants-cell="{ row }">
        <span v-if="row.original.kind === 'dedicated'">owned by {{ row.original.owner }}</span>
        <div v-else class="flex flex-wrap gap-1">
          <UBadge v-for="slug in row.original.grants" :key="slug" color="neutral" variant="outline" :label="slug">
            <template #trailing>
              <button type="button" class="ml-1 text-error" :aria-label="`Revoke ${row.original.name} from ${slug}`" @click="grant(row.original, slug, false)"><UIcon name="i-lucide-x" /></button>
            </template>
          </UBadge>
          <span v-if="!row.original.grants.length" class="text-muted">none</span>
        </div>
      </template>
      <template #grant-cell="{ row }">
        <form v-if="row.original.kind === 'shared'" class="flex gap-2" @submit.prevent="grant(row.original, grantTo[row.original.id] || '', true)">
          <UInput v-model="grantTo[row.original.id]" placeholder="tenant slug" :aria-label="`Tenant to grant ${row.original.name}`" class="w-36" size="sm" />
          <UButton type="submit" size="sm" color="neutral" variant="outline" label="Grant" />
        </form>
      </template>
    </UTable>
  </section>
  <section aria-labelledby="new-pool-h" class="space-y-3">
    <h2 id="new-pool-h" class="text-base font-semibold">Create a pool</h2>
    <form class="flex flex-wrap items-end gap-3" aria-label="Create a pool" @submit.prevent="create">
      <UFormField label="Name" name="p-name"><UInput id="p-name" v-model="form.name" required maxlength="64" class="w-48" /></UFormField>
      <UFormField label="Kind" name="p-kind"><USelect id="p-kind" v-model="form.kind" :items="[{ label: 'Shared', value: 'shared' }, { label: 'Dedicated', value: 'dedicated' }]" class="w-36" /></UFormField>
      <UFormField v-if="form.kind === 'dedicated'" label="Owner tenant" name="p-owner"><UInput id="p-owner" v-model="form.tenant" required class="w-40" /></UFormField>
      <UButton type="submit" icon="i-lucide-plus" label="Create" />
    </form>
  </section>
</template>
