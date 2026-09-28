<script setup lang="ts">
import type { DeploymentStorage } from "~~/shared/types/api";

const api = useApi();
const act = useAct();
const session = useSession();
const after = ref<string | null>(null);
const { data, refresh } = await useAsyncData(() => `platform-tenants-${after.value}`,
  () => api<{ tenants: any[]; next: string | null }>(`/api/v1/admin/tenants?limit=50${after.value ? `&after=${encodeURIComponent(after.value)}` : ""}`), { watch: [after] });
const quotas = reactive<Record<string, number | undefined>>({});
const slug = ref("");
const confirmSuspend = ref<any | null>(null);
// The deployment's defaults: what a tenant's blank setting inherits (R01).
const { data: deployment } = await useAsyncData("platform-storage-defaults",
  () => api<DeploymentStorage>("/api/v1/admin/storage").catch(() => null));
const editing = ref<any | null>(null);
async function saveStorage(t: any, body: Record<string, number | null>) {
  if (await act(`Storage policy of ${t.slug}`, () => api(`/api/v1/admin/tenants/${t.slug}/storage`, { method: "PUT", body }))) {
    editing.value = null;
    await refresh();
  }
}

async function setQuota(t: any) {
  const gib = quotas[t.slug];
  if (!gib || gib <= 0) return;
  await act(`Quota of ${t.slug}`, () => api(`/api/v1/admin/tenants/${t.slug}/quota`, { method: "PUT", body: { bytes: Math.round(gib * 2 ** 30) } }));
  await refresh();
}
async function clearQuota(t: any) {
  await act(`Default quota of ${t.slug}`, () => api(`/api/v1/admin/tenants/${t.slug}/quota`, { method: "DELETE" }));
  await refresh();
}
async function toggle(t: any) {
  confirmSuspend.value = null;
  if (await act(`${t.active ? "Suspend" : "Reactivate"} ${t.slug}`, () => api(`/api/v1/admin/tenants/${t.slug}/${t.active ? "suspend" : "reactivate"}`, { method: "POST", body: {} }))) {
    await refresh();
    await session.refreshTenants();
  }
}
async function create() {
  if (await act(`Create ${slug.value}`, () => api("/api/v1/admin/tenants", { method: "POST", body: { slug: slug.value } }))) {
    slug.value = "";
    await refresh();
  }
}
const columns = [
  { accessorKey: "slug", header: "Tenant" }, { accessorKey: "kind", header: "Kind" }, { accessorKey: "active", header: "State" },
  { accessorKey: "members", header: "Members" }, { accessorKey: "usage_bytes", header: "Storage" }, { id: "quota", header: "Quota" }, { id: "actions", header: "Actions" },
];
</script>

<template>
  <section aria-labelledby="tenants-h" class="space-y-3">
    <h2 id="tenants-h" class="text-base font-semibold">Tenants</h2>
    <UTable :data="data?.tenants ?? []" :columns="columns" caption="Tenants" class="rounded-lg border border-default">
      <template #slug-cell="{ row }">
        <ULink v-if="row.original.active" :to="`/t/${row.original.slug}/admin`" class="text-primary underline font-medium">{{ row.original.slug }}</ULink>
        <span v-else class="font-medium">{{ row.original.slug }}</span>
      </template>
      <template #active-cell="{ row }"><StateBadge :state="row.original.active ? 'online' : 'suspended'" :label="row.original.active ? 'active' : 'suspended'" /></template>
      <template #usage_bytes-cell="{ row }">{{ fmtBytes(row.original.usage_bytes) }}</template>
      <template #quota-cell="{ row }">
        <form class="flex items-center gap-2" @submit.prevent="setQuota(row.original)">
          <UInputNumber v-model="quotas[row.original.slug]" :min="1" :placeholder="row.original.quota_bytes ? (row.original.quota_bytes / 2 ** 30).toFixed(0) : 'unlimited'"
            :aria-label="`Quota of ${row.original.slug} in GiB`" class="w-40" />
          <span class="text-sm text-muted">GiB</span>
          <UButton type="submit" size="sm" color="neutral" variant="outline" label="Set" />
          <UButton v-if="row.original.quota_set" size="sm" color="neutral" variant="ghost" label="Default" @click="clearQuota(row.original)" />
        </form>
        <p class="text-xs text-muted mt-1">{{ row.original.quota_bytes ? `${Math.round((100 * row.original.usage_bytes) / row.original.quota_bytes)}% of ${fmtBytes(row.original.quota_bytes)} used` : "no limit" }}</p>
      </template>
      <template #actions-cell="{ row }">
        <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-sliders-horizontal" class="mr-2" :aria-label="`Storage policy of ${row.original.slug}`" @click="editing = row.original">Storage</UButton>
        <UButton v-if="row.original.active" size="sm" color="error" variant="soft" icon="i-lucide-pause" :aria-label="`Suspend ${row.original.slug}`" @click="confirmSuspend = row.original">Suspend</UButton>
        <UButton v-else size="sm" icon="i-lucide-play" :aria-label="`Reactivate ${row.original.slug}`" @click="toggle(row.original)">Reactivate</UButton>
      </template>
    </UTable>
    <div class="flex gap-2">
      <UButton v-if="after" color="neutral" variant="outline" label="First page" @click="after = null" />
      <UButton v-if="data?.next" color="neutral" variant="outline" label="Next page" trailing-icon="i-lucide-arrow-right" @click="after = data!.next" />
    </div>
  </section>
  <section aria-labelledby="new-tenant-h" class="space-y-3">
    <h2 id="new-tenant-h" class="text-base font-semibold">Create an organization</h2>
    <form class="flex flex-wrap items-end gap-3" aria-label="Create an organization" @submit.prevent="create">
      <UFormField label="Slug" name="slug" help="Lowercase letters, digits and inner hyphens"><UInput id="t-slug" v-model="slug" required class="w-56" /></UFormField>
      <UButton type="submit" icon="i-lucide-plus" label="Create" />
    </form>
    <p class="text-sm text-muted">A new organization has no members: add its first administrator from its Tenant admin page.</p>
  </section>
  <UModal :open="!!editing" :title="`Storage policy · ${editing?.slug}`" description="Blank fields inherit the deployment's configuration." @update:open="(o) => !o && (editing = null)">
    <template #body>
      <StoragePolicyForm v-if="editing" :id="`tenant-${editing.slug}`"
        :policy="{ quota_bytes: editing.quota_set ? editing.quota_bytes : null, log_retention_ms: editing.log_retention_ms ?? null, artifact_retention_ms: editing.artifact_retention_ms ?? null }"
        :inherited="{ quota_bytes: deployment?.tenant_quota_bytes ?? 0, log_retention_ms: deployment?.log_retention_ms ?? 14 * 86_400_000, artifact_retention_ms: deployment?.artifact_retention_ms ?? 90 * 86_400_000 }"
        @save="(body) => saveStorage(editing, body)" />
    </template>
  </UModal>
  <UModal :open="!!confirmSuspend" :title="`Suspend ${confirmSuspend?.slug}?`" description="Its credentials and invitations are revoked, its jobs are cancelled, and its members lose access at once." @update:open="(o) => !o && (confirmSuspend = null)">
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="ghost" label="Keep active" @click="confirmSuspend = null" />
        <UButton color="error" label="Suspend" @click="toggle(confirmSuspend)" />
      </div>
    </template>
  </UModal>
</template>
