<script setup lang="ts">
const api = useApi();
const act = useAct();
const { data, refresh } = await useAsyncData("registrations", () => api<{ pending: any[] }>("/api/v1/admin/registrations?limit=100"));
async function decide(a: any, approve: boolean) {
  if (await act(`${approve ? "Approve" : "Reject"} ${a.display_name}`, () => api(`/api/v1/admin/registrations/${a.user}/${approve ? "approve" : "reject"}`, { method: "POST", body: {} }))) await refresh();
}
const columns = [{ accessorKey: "display_name", header: "Applicant" }, { accessorKey: "applied_ms", header: "Applied" }, { id: "actions", header: "Actions" }];
</script>

<template>
  <section aria-labelledby="reg-h" class="space-y-3">
    <h2 id="reg-h" class="text-base font-semibold">Pending registrations</h2>
    <UTable :data="data?.pending ?? []" :columns="columns" caption="Pending registrations" empty="No applications are waiting." class="rounded-lg border border-default">
      <template #display_name-cell="{ row }">
        <div class="font-medium">{{ row.original.display_name }}</div>
        <div class="text-xs text-muted font-mono">{{ shortId(row.original.user) }}</div>
      </template>
      <template #applied_ms-cell="{ row }"><RelTime :ms="row.original.applied_ms" /></template>
      <template #actions-cell="{ row }">
        <div class="flex gap-2 justify-end">
          <UButton size="sm" icon="i-lucide-check" :aria-label="`Approve ${row.original.display_name}`" @click="decide(row.original, true)">Approve</UButton>
          <UButton size="sm" color="error" variant="soft" icon="i-lucide-x" :aria-label="`Reject ${row.original.display_name}`" @click="decide(row.original, false)">Reject</UButton>
        </div>
      </template>
    </UTable>
  </section>
</template>
