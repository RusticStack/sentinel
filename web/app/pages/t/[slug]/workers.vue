<script setup lang="ts">
import type { Pool, Worker } from "~~/shared/types/api";

// The pools this tenant may use: each worker's reported capacity, what it
// holds now and what is free on its host, labels, warm cache, transport,
// and drain for platform administrators. Reservations are totals: a shared
// worker also serves other tenants.
const route = useRoute();
const api = useApi();
const act = useAct();
const session = useSession();
const slug = route.params.slug as string;
useHead({ title: `Workers · ${slug} · Sentinel` });

const { data, refresh } = await useAsyncData(`workers-${slug}`, () => api<{ pools: Pool[] }>(`/api/v1/workers?tenant=${slug}`));
usePolling(refresh, 5000);

async function drain(w: Worker) {
  await act(`${w.draining ? "Undrain" : "Drain"} ${w.name}`, () => api(`/api/v1/workers/${w.id}/${w.draining ? "undrain" : "drain"}`, { method: "POST", body: {} }));
  await refresh();
}
const used = (w: Worker) => (w.capacity?.cpu_millis ? Math.min(100, Math.round((100 * w.held.cpu_millis) / w.capacity.cpu_millis)) : null);
const columns = [
  { id: "worker", header: "Worker" }, { id: "state", header: "State" }, { id: "capacity", header: "Capacity" },
  { id: "held", header: "Held" }, { id: "free", header: "Free on host" }, { id: "labels", header: "Labels" },
  { id: "cache", header: "Cache" }, { id: "transport", header: "Transport" }, { id: "actions", header: "Actions" },
];
</script>

<template>
  <SPage id="workers" :title="`Workers · ${slug}`">
    <UEmpty v-if="data && !data.pools.length" icon="i-lucide-server-off" title="No worker pools" description="This tenant has no dedicated or granted pools." />
    <section v-for="pool in data?.pools ?? []" :key="pool.id" :aria-labelledby="`pool-${pool.id}`" class="space-y-3">
      <h2 :id="`pool-${pool.id}`" class="text-base font-semibold flex items-center gap-2">
        {{ pool.name }}
        <UBadge color="neutral" variant="subtle" :label="`${pool.kind} pool`" />
        <UBadge v-if="!pool.active" color="warning" variant="subtle" label="inactive" />
      </h2>
      <UTable :data="pool.workers" :columns="columns" :caption="`Workers in ${pool.name}`" empty="No workers enrolled." class="rounded-lg border border-default">
        <template #worker-cell="{ row }">
          <div class="font-medium">{{ row.original.name }}</div>
          <div class="text-xs text-muted font-mono">{{ row.original.arch }} · {{ shortId(row.original.id) }}</div>
          <div class="text-xs text-muted">{{ row.original.software ?? "software not reported" }} · protocol {{ row.original.protocol }}</div>
        </template>
        <template #state-cell="{ row }">
          <StateBadge :state="!row.original.connected ? 'offline' : row.original.draining ? 'draining' : 'online'" />
          <div v-if="!row.original.connected" class="text-xs text-muted mt-1">seen <RelTime :ms="row.original.last_seen_ms" /></div>
        </template>
        <template #capacity-cell="{ row }">
          <span v-if="row.original.capacity">{{ cpu(row.original.capacity.cpu_millis) }}, {{ fmtBytes(row.original.capacity.memory_bytes) }}<template v-if="row.original.capacity.disk_bytes">, {{ fmtBytes(row.original.capacity.disk_bytes) }} disk</template></span>
          <span v-else class="text-muted">not reported</span>
        </template>
        <template #held-cell="{ row }">
          <div>{{ row.original.held_attempts }} attempt{{ row.original.held_attempts === 1 ? "" : "s" }}</div>
          <div class="text-xs text-muted">{{ cpu(row.original.held.cpu_millis) }}, {{ fmtBytes(row.original.held.memory_bytes) }}</div>
          <!-- A plain bar: the component library's progress formats its value
               with the runtime's locale, which differs between server and browser. -->
          <div v-if="used(row.original) !== null" class="mt-1 h-1.5 w-28 rounded-full bg-elevated overflow-hidden" role="img" :aria-label="`${used(row.original)}% of CPU reserved`">
            <div class="h-full bg-primary" :style="{ width: `${used(row.original)}%` }" />
          </div>
        </template>
        <template #free-cell="{ row }">
          {{ cpu(row.original.free.cpu_millis) }}, {{ fmtBytes(row.original.free.memory_bytes) }}<template v-if="row.original.free.disk_bytes !== undefined">, {{ fmtBytes(row.original.free.disk_bytes) }} disk</template>
          <div v-if="(row.original.host_workers ?? 0) > 1" class="text-xs text-muted">host shared by {{ row.original.host_workers }} workers</div>
        </template>
        <template #labels-cell="{ row }">
          <div class="flex flex-wrap gap-1">
            <UBadge v-for="l in row.original.labels" :key="l" color="neutral" variant="outline" size="sm" :label="l" />
            <span v-if="!row.original.labels.length" class="text-muted">—</span>
          </div>
        </template>
        <template #cache-cell="{ row }">{{ row.original.cache_bytes ? fmtBytes(row.original.cache_bytes) : "—" }}</template>
        <template #transport-cell="{ row }">
          <template v-if="row.original.transport">
            {{ row.original.transport.path }}<template v-if="row.original.transport.rtt_ns">, {{ fmtNs(row.original.transport.rtt_ns) }} RTT</template>
            <div v-if="row.original.transport.reconnects" class="text-xs text-muted">{{ row.original.transport.reconnects }} reconnects</div>
          </template>
          <span v-else class="text-muted">—</span>
        </template>
        <template #actions-cell="{ row }">
          <UButton v-if="session.me.value?.super_admin" size="sm" color="neutral" variant="outline" :icon="row.original.draining ? 'i-lucide-play' : 'i-lucide-pause'" :aria-label="`${row.original.draining ? 'Undrain' : 'Drain'} ${row.original.name}`" @click="drain(row.original)">
            {{ row.original.draining ? "Undrain" : "Drain" }}
          </UButton>
        </template>
      </UTable>
    </section>
  </SPage>
</template>
