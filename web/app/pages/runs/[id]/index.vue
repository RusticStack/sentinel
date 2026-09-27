<script setup lang="ts">
import type { Explanation, Run } from "~~/shared/types/api";
import { phasesOf } from "~/components/PhaseBar.vue";

// One run: its graph, each job's phases, cancel and rerun, why failed jobs
// failed, cache outcomes and artifacts — kept current by the run stream.
const route = useRoute();
const api = useApi();
const act = useAct();
const id = route.params.id as string;

const { data: run, error } = await useAsyncData(`run-${id}`, () => api<Run>(`/api/v1/runs/${id}`));
if (error.value) throw createError({ statusCode: error.value instanceof ApiError && error.value.status ? error.value.status : 500, statusMessage: error.value.message, fatal: false });
const { data: explain } = await useAsyncData(`explain-${id}`, () => api<Explanation>(`/api/v1/runs/${id}/pipeline`).catch(() => null));
// The owning tenant's slug (for downloads and navigation) and repository.
const { data: arts } = await useAsyncData(`arts-${id}`, () => api<{ tenant: string; artifacts: any[] }>(`/api/v1/runs/${id}/artifacts`).catch(() => null));
const slug = computed(() => arts.value?.tenant ?? null);
const { data: repos } = await useRepos(() => slug.value ?? "");
const repoName = computed(() => repos.value?.repos.find((r) => r.id === run.value?.repo)?.name ?? null);
if (slug.value) useState("tenant").value = slug.value;

useHead({ title: () => `Run ${shortId(id)} · Sentinel` });
const { status, refused } = useRunStream(id, run);

// The render's clock travels with the page, so the browser's first render
// matches the server's; it ticks once mounted.
const now = useState(`now-${id}`, () => Date.now());
let ticker: ReturnType<typeof setInterval> | undefined;
onMounted(() => { ticker = setInterval(() => (now.value = Date.now()), 1000); });
onBeforeUnmount(() => clearInterval(ticker));

const finished = computed(() => !!run.value?.jobs.every((j) => j.terminal));
const scale = computed(() => Math.max(1, ...(run.value?.jobs ?? []).map((j) => phasesOf(j.timestamps, now.value).reduce((a, p) => a + p.ms, 0))));
const failed = computed(() => (run.value?.jobs ?? []).filter((j) => j.attempt && j.terminal && !["passed", "skipped", "canceled"].includes(j.state)));

const { data: caches } = await useAsyncData(`caches-${id}`, async () => {
  const rows: any[] = [];
  const jobs = (run.value?.jobs ?? []).filter((j) => j.attempt);
  const summaries = await Promise.all(jobs.map((j) => api<any>(`/api/v1/attempts/${j.attempt}/summary`).then((s) => [j, s] as const).catch(() => [j, null] as const)));
  for (const [j, s] of summaries) {
    if (!s?.present) continue;
    for (const c of s.caches) rows.push({ job: j.name, name: c.name, outcome: c.outcome, backend: c.reflink ? "reflink" : "copy", bytes: c.bytes, copied: c.copied_bytes, restore: c.clone_ns, publish: c.publish, costly: c.costly_hit });
    if (s.image_present !== null && s.image_present !== undefined) rows.push({ job: j.name, name: "image", outcome: s.image_present ? "hit" : "miss", backend: "image store", bytes: null, copied: null, restore: null, publish: null, costly: false });
  }
  return rows;
}, { server: false, lazy: true });

async function cancelRun() { await act("Cancel run", () => api(`/api/v1/runs/${id}/cancel`, { method: "POST", body: {} })); }
async function jobAction(job: { id: string; name: string; terminal: boolean }) {
  await act(`${job.terminal ? "Rerun" : "Cancel"} ${job.name}`, () => api(`/api/v1/jobs/${job.id}/${job.terminal ? "rerun" : "cancel"}`, { method: "POST", body: {} }));
}

const openManifest = ref<Record<string, any>>({});
async function toggleManifest(a: any) {
  if (openManifest.value[a.id]) { delete openManifest.value[a.id]; return; }
  const detail = await act(`Files of ${a.name}`, () => api<any>(`/api/v1/runs/${id}/artifacts/${a.id}`));
  if (detail?.manifest) openManifest.value[a.id] = detail;
}

const jobColumns = [
  { accessorKey: "name", header: "Job" },
  { accessorKey: "state", header: "State" },
  { accessorKey: "failure_class", header: "Failure class" },
  { id: "phases", header: "Phases" },
  { id: "log", header: "Log" },
  { id: "actions", header: "Actions" },
];
const cacheColumns = [
  { accessorKey: "job", header: "Job" }, { accessorKey: "name", header: "Cache" }, { accessorKey: "outcome", header: "Outcome" },
  { accessorKey: "backend", header: "Backend" }, { accessorKey: "bytes", header: "Size" }, { accessorKey: "copied", header: "Copied" },
  { accessorKey: "restore", header: "Restore" }, { accessorKey: "publish", header: "Publish" },
];
const artifactColumns = [
  { accessorKey: "name", header: "Artifact" }, { accessorKey: "job_name", header: "Job" }, { accessorKey: "state", header: "State" },
  { accessorKey: "entries", header: "Entries" }, { accessorKey: "bytes", header: "Size" }, { accessorKey: "retain_until_ms", header: "Kept until" }, { id: "files", header: "Files" },
];
</script>

<template>
  <SPage id="run" :title="`Run ${shortId(id)}`">
    <template #actions>
      <UBadge v-if="status === 'busy'" color="warning" variant="subtle" icon="i-lucide-hourglass" label="Updates paused: controller busy" />
      <UBadge v-else-if="status === 'lost' || status === 'reconnecting'" color="warning" variant="subtle" icon="i-lucide-wifi-off" label="Reconnecting…" />
      <UBadge v-else-if="status === 'live' && !finished" color="info" variant="subtle" icon="i-lucide-radio" label="Live" />
      <UButton v-if="run && !finished" color="error" variant="soft" icon="i-lucide-square" label="Cancel run" @click="cancelRun" />
    </template>

    <UAlert v-if="refused" color="error" variant="subtle" icon="i-lucide-lock" :title="refused" description="The page stopped following this run." role="alert"
      :actions="[{ label: 'Back to your tenants', to: '/' }]" />

    <template v-if="run">
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-sm">
        <dt class="text-muted">State</dt>
        <dd class="flex items-center gap-2"><StateBadge :state="run.state" /><span v-if="run.cancel_requested && !finished" class="text-muted">cancel requested</span></dd>
        <dt class="text-muted">Trigger</dt><dd>{{ words(run.trigger) }}</dd>
        <dt class="text-muted">Commit</dt><dd><code class="text-xs break-all">{{ run.sha }}</code></dd>
        <dt class="text-muted">Repository</dt>
        <dd><ULink v-if="slug && repoName" :to="`/t/${slug}?repo=${encodeURIComponent(repoName)}`" class="text-primary underline">{{ slug }}/{{ repoName }}</ULink><span v-else>{{ shortId(run.repo) }}</span></dd>
        <dt class="text-muted">Created</dt><dd><RelTime :ms="run.created_ms" /></dd>
      </dl>

      <section aria-labelledby="jobs-h" class="space-y-3">
        <h2 id="jobs-h" class="text-base font-semibold">Jobs</h2>
        <JobGraph v-if="explain" :explain="explain" :jobs="run.jobs" :run="id" />
        <UTable :data="run.jobs" :columns="jobColumns" caption="Jobs" class="rounded-lg border border-default">
          <template #state-cell="{ row }">
            <div class="flex flex-col gap-1 items-start">
              <StateBadge :state="row.original.state" />
              <span v-if="row.original.cancel_requested && !row.original.terminal" class="text-xs text-muted">cancel requested</span>
            </div>
          </template>
          <template #failure_class-cell="{ row }">{{ words(row.original.failure_class) }}</template>
          <template #phases-cell="{ row }"><PhaseBar :t="row.original.timestamps" :scale="scale" :now="now" /></template>
          <template #log-cell="{ row }">
            <ULink v-if="row.original.attempt" :to="`/runs/${id}/logs/${row.original.attempt}`" :aria-label="`Log of ${row.original.name}`" class="text-primary underline">Log</ULink>
            <span v-else class="text-muted">—</span>
            <span v-if="row.original.log_state && row.original.log_state !== 'complete' && row.original.terminal" class="text-xs text-muted"> ({{ row.original.log_state }})</span>
          </template>
          <template #actions-cell="{ row }">
            <UButton size="sm" :color="row.original.terminal ? 'neutral' : 'error'" :variant="row.original.terminal ? 'outline' : 'soft'"
              :icon="row.original.terminal ? 'i-lucide-rotate-cw' : 'i-lucide-square'" :aria-label="`${row.original.terminal ? 'Rerun' : 'Cancel'} ${row.original.name}`" @click="jobAction(row.original)">
              {{ row.original.terminal ? "Rerun" : "Cancel" }}
            </UButton>
          </template>
        </UTable>
      </section>

      <FailureSummary v-for="job in failed" :key="job.attempt!" :job="job" :run="id" />

      <section v-if="caches?.length" aria-labelledby="caches-h" class="space-y-3">
        <h2 id="caches-h" class="text-base font-semibold">Caches</h2>
        <UTable :data="caches" :columns="cacheColumns" caption="Cache outcomes" class="rounded-lg border border-default">
          <template #outcome-cell="{ row }">
            <StateBadge :state="row.original.outcome === 'hit' ? 'hit' : 'miss'" :label="row.original.outcome === 'hit' ? 'hit' : `miss: ${words(row.original.outcome)}`" />
            <span v-if="row.original.costly" class="text-xs text-muted"> costly hit</span>
          </template>
          <template #bytes-cell="{ row }">{{ fmtBytes(row.original.bytes) }}</template>
          <template #copied-cell="{ row }">{{ fmtBytes(row.original.copied) }}</template>
          <template #restore-cell="{ row }">{{ fmtNs(row.original.restore) }}</template>
          <template #publish-cell="{ row }">{{ row.original.publish ?? "—" }}</template>
        </UTable>
      </section>

      <section v-if="arts?.artifacts.length" aria-labelledby="artifacts-h" class="space-y-3">
        <h2 id="artifacts-h" class="text-base font-semibold">Artifacts</h2>
        <UTable :data="arts.artifacts" :columns="artifactColumns" caption="Artifacts" class="rounded-lg border border-default">
          <template #state-cell="{ row }"><StateBadge :state="row.original.state === 'captured' ? 'passed' : row.original.state === 'failed' ? 'failed' : 'skipped'" :label="row.original.state" /></template>
          <template #bytes-cell="{ row }">{{ fmtBytes(row.original.bytes) }}</template>
          <template #retain_until_ms-cell="{ row }"><RelTime :ms="row.original.retain_until_ms" /></template>
          <template #files-cell="{ row }">
            <div v-if="row.original.state === 'captured'">
              <UButton size="sm" color="neutral" variant="outline" :aria-expanded="!!openManifest[row.original.id]" :aria-label="`Files of ${row.original.name}`" @click="toggleManifest(row.original)">Files</UButton>
              <ul v-if="openManifest[row.original.id]" class="mt-2 space-y-1 text-xs">
                <li v-for="en in openManifest[row.original.id].manifest.entries.slice(0, 500)" :key="en.path">
                  <a :href="`/api/v1/tenants/${openManifest[row.original.id].tenant}/objects/${en.digest}`" :download="en.path.split('/').pop()" class="text-primary underline">{{ en.path }}</a>
                  <span class="text-muted"> {{ fmtBytes(en.len) }}</span>
                </li>
              </ul>
            </div>
          </template>
        </UTable>
      </section>
    </template>
  </SPage>
</template>
