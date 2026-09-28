<script setup lang="ts">
import type { Backups } from "~~/shared/types/api";

// Scheduled online backups (R04): where they go, the last result, every
// backup kept, and one now on request.
const api = useApi();
const act = useAct();
const { data, refresh } = await useAsyncData("platform-backups", () => api<Backups>("/api/v1/admin/backups"));
usePolling(() => refresh(), 5000);
async function now() {
  if (await act("Backup", () => api("/api/v1/admin/backups", { method: "POST", body: {} }))) await refresh();
}
const columns = [
  { accessorKey: "id", header: "Backup" }, { id: "size", header: "Database" }, { accessorKey: "objects", header: "Objects" },
  { id: "took", header: "Took" }, { id: "key", header: "Key" },
];
</script>

<template>
  <section v-if="data" aria-labelledby="backups-h" class="space-y-3">
    <h2 id="backups-h" class="text-base font-semibold">Backups</h2>
    <p v-if="!data.configured" class="text-sm text-muted">Not configured: set <code>[backup] dir</code> in the controller's configuration, on another disk. Until then use <code>sentinel admin backup create</code> beside a stopped controller.</p>
    <template v-else-if="data.scheduler">
      <UAlert v-if="data.scheduler.last_failure" color="error" variant="subtle" icon="i-lucide-archive-x" role="alert" title="The last backup failed" :description="data.scheduler.last_failure" />
      <div class="flex flex-wrap items-center gap-3 text-sm">
        <span>Every {{ Math.round(data.scheduler.interval_secs / 60) }} min into <code>{{ data.scheduler.target }}</code>, the newest {{ data.scheduler.keep }} kept.</span>
        <span>Last success <RelTime :ms="data.scheduler.last_success_ms" />.</span>
        <UButton size="sm" icon="i-lucide-archive" :loading="data.scheduler.running" :disabled="data.scheduler.running" :label="data.scheduler.running ? 'Backing up' : 'Back up now'" @click="now" />
      </div>
      <UTable :data="data.backups" :columns="columns" caption="Backups" empty="No backup yet." class="rounded-lg border border-default">
        <template #id-cell="{ row }"><code>{{ row.original.id }}</code></template>
        <template #size-cell="{ row }">{{ fmtBytes(row.original.metadata_bytes) }}</template>
        <template #took-cell="{ row }">{{ fmtMs(row.original.took_ms) }}</template>
        <template #key-cell="{ row }">{{ row.original.key_required ? `key ids ${row.original.key_ids.join(", ")}` : "not needed" }}</template>
      </UTable>
      <p class="text-sm text-muted">The master key is never in a backup: keep <code>master.key</code> in a separate, offline place. Verify with <code>sentinel admin backup verify</code>; restore with <code>sentinel admin restore</code> (<a class="text-primary underline" href="https://github.com/RusticStack/sentinel/blob/main/docs/backup.md">backup and restore</a>).</p>
    </template>
  </section>
</template>
