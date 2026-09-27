<script setup lang="ts">
const props = defineProps<{ slug: string }>();
const api = useApi();
const act = useAct();
const session = useSession();
const ROLES = [{ label: "Reader", value: "reader" }, { label: "Operator", value: "operator" }, { label: "Admin", value: "admin" }];

const { data, refresh } = await useAsyncData(`members-${props.slug}`, () => api<{ members: any[]; next: string | null }>(`/api/v1/tenants/${props.slug}/members?limit=100`));
const who = ref("");
const role = ref("reader");
const confirmRemove = ref<any | null>(null);

async function setRole(m: any, next: string) {
  const done = await act(`Role of ${m.username || m.display_name}`, () => api(`/api/v1/tenants/${props.slug}/members/${m.user}`, { method: "PUT", body: { role: next } }));
  await refresh();
  if (done) await session.refreshTenants();
}
async function add() {
  if (await act(`Add ${who.value}`, () => api(`/api/v1/tenants/${props.slug}/members/${encodeURIComponent(who.value)}`, { method: "PUT", body: { role: role.value } }))) {
    who.value = "";
    await refresh();
  }
}
async function remove() {
  const m = confirmRemove.value;
  confirmRemove.value = null;
  if (await act(`Remove ${m.username || m.display_name}`, () => api(`/api/v1/tenants/${props.slug}/members/${m.user}`, { method: "DELETE" }))) {
    await refresh();
    await session.refreshTenants();
  }
}
const columns = [{ id: "member", header: "Member" }, { accessorKey: "kind", header: "Kind" }, { id: "role", header: "Role" }, { id: "actions", header: "Actions" }];
</script>

<template>
  <section aria-labelledby="members-h" class="space-y-3">
    <h2 id="members-h" class="text-base font-semibold">Members</h2>
    <UTable :data="data?.members ?? []" :columns="columns" caption="Members" class="rounded-lg border border-default">
      <template #member-cell="{ row }">
        <div class="font-medium">{{ row.original.username || row.original.display_name }}</div>
        <div class="text-xs text-muted font-mono">{{ shortId(row.original.user) }}</div>
        <UBadge v-if="!row.original.active" color="warning" variant="subtle" label="inactive" size="sm" />
      </template>
      <template #role-cell="{ row }">
        <USelect :model-value="row.original.role" :items="row.original.kind === 'service' ? ROLES.filter((r) => r.value !== 'admin') : ROLES"
          :aria-label="`Role of ${row.original.username || row.original.display_name}`" class="w-36" @update:model-value="(v: string) => setRole(row.original, v)" />
      </template>
      <template #actions-cell="{ row }">
        <UButton size="sm" color="error" variant="ghost" icon="i-lucide-user-minus" :aria-label="`Remove ${row.original.username || row.original.display_name}`" @click="confirmRemove = row.original">
          Remove
        </UButton>
      </template>
    </UTable>
    <p v-if="data?.next" class="text-sm text-muted">Only the first 100 members are shown.</p>
  </section>

  <section aria-labelledby="add-h" class="space-y-3">
    <h2 id="add-h" class="text-base font-semibold">Add a member</h2>
    <form class="flex flex-wrap items-end gap-3" aria-label="Add a member" @submit.prevent="add">
      <UFormField label="Username or user id" name="who"><UInput id="m-user" v-model="who" required autocomplete="off" class="w-56" /></UFormField>
      <UFormField label="Role" name="role"><USelect id="m-role" v-model="role" :items="ROLES" class="w-36" /></UFormField>
      <UButton type="submit" icon="i-lucide-user-plus" label="Add or change" />
    </form>
  </section>

  <UModal :open="!!confirmRemove" :title="`Remove ${confirmRemove?.username || confirmRemove?.display_name}?`"
    description="Their credentials for this tenant are revoked at once, and open pages lose access." @update:open="(o) => !o && (confirmRemove = null)">
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="ghost" label="Keep" @click="confirmRemove = null" />
        <UButton color="error" label="Remove" @click="remove" />
      </div>
    </template>
  </UModal>
</template>
