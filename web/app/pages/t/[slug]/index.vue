<script setup lang="ts">
import type { RunSummary } from "~~/shared/types/api";

// A repository's runs, newest first, narrowed by ref, pull request or
// commit prefix — each filter an index range on the controller. The first
// page refreshes itself while open.
const route = useRoute();
const router = useRouter();
const api = useApi();
const slug = computed(() => route.params.slug as string);
useCookie("sentinel-tenant", { sameSite: "lax", maxAge: 60 * 60 * 24 * 365 }).value = slug.value;
useHead({ title: () => `Runs · ${slug.value} · Sentinel` });

const { data: repos } = await useRepos(slug);
const repoCookie = useCookie<string | null>(`sentinel-repo-${slug.value}`, { sameSite: "lax", maxAge: 60 * 60 * 24 * 365 });
const repo = computed(() => (route.query.repo as string) || (repos.value?.repos.some((r) => r.name === repoCookie.value) ? repoCookie.value : repos.value?.repos[0]?.name) || null);

type Kind = "all" | "ref" | "pr" | "sha";
const kinds = [{ label: "All runs", value: "all" }, { label: "Ref or branch", value: "ref" }, { label: "Pull request", value: "pr" }, { label: "Commit SHA", value: "sha" }];
const kind = ref<Kind>(route.query.ref ? "ref" : route.query.pr ? "pr" : route.query.sha ? "sha" : "all");
const value = ref(String(route.query.ref || route.query.pr || route.query.sha || ""));
const repoPick = ref<string | undefined>(repo.value ?? undefined);

const query = computed(() => {
  const q = new URLSearchParams({ limit: "50" });
  for (const k of ["ref", "pr", "sha", "before"]) if (route.query[k]) q.set(k, String(route.query[k]));
  return q.toString();
});
const { data: page, refresh, error } = await useAsyncData(
  () => `runs-${slug.value}-${repo.value}-${query.value}`,
  () => (repo.value ? api<{ runs: RunSummary[]; next: string | null }>(`/api/v1/tenants/${slug.value}/repos/${encodeURIComponent(repo.value)}/runs?${query.value}`) : Promise.resolve({ runs: [], next: null })),
  { watch: [repo, query] },
);

function apply() {
  const q: Record<string, string> = { repo: repoPick.value || "" };
  if (kind.value !== "all" && value.value.trim()) q[kind.value] = value.value.trim();
  if (repoPick.value) repoCookie.value = repoPick.value;
  router.push({ query: q });
}

let timer: ReturnType<typeof setInterval> | undefined;
onMounted(() => { timer = setInterval(() => { if (document.visibilityState === "visible" && !route.query.before) refresh(); }, 10000); });
onBeforeUnmount(() => clearInterval(timer));

const columns = [
  { accessorKey: "id", header: "Run" },
  { accessorKey: "state", header: "State" },
  { accessorKey: "trigger", header: "Trigger" },
  { accessorKey: "ref", header: "Ref" },
  { accessorKey: "pr", header: "PR" },
  { accessorKey: "sha", header: "Commit" },
  { accessorKey: "created_ms", header: "Created" },
];
</script>

<template>
  <SPage id="runs" :title="`Runs · ${slug}`">
    <UEmpty v-if="repos && !repos.repos.length" icon="i-lucide-folder-git-2" title="No repositories" description="There are no repositories you can read in this tenant." />
    <template v-else>
      <form class="flex flex-wrap items-end gap-3" role="search" aria-label="Filter runs" @submit.prevent="apply">
        <UFormField label="Repository" name="repo">
          <USelect id="f-repo" v-model="repoPick" :items="(repos?.repos ?? []).map((r) => ({ label: r.name, value: r.name }))" class="w-44" />
        </UFormField>
        <UFormField label="Filter" name="kind">
          <USelect id="f-kind" v-model="kind" :items="kinds" class="w-40" />
        </UFormField>
        <UFormField label="Value" name="value">
          <UInput id="f-value" v-model="value" :disabled="kind === 'all'" placeholder="main, 42 or a SHA prefix" class="w-56" />
        </UFormField>
        <UButton type="submit" icon="i-lucide-search" label="Show runs" />
      </form>

      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error.message" />
      <UTable :data="page?.runs ?? []" :columns="columns" :caption="`Runs of ${repo}`" empty="No runs match." class="rounded-lg border border-default">
        <template #id-cell="{ row }">
          <ULink :to="`/runs/${row.original.id}`" class="font-medium text-primary hover:underline">{{ shortId(row.original.id) }}</ULink>
        </template>
        <template #state-cell="{ row }"><StateBadge :state="row.original.state" /></template>
        <template #trigger-cell="{ row }">{{ words(row.original.trigger) }}</template>
        <template #ref-cell="{ row }"><code class="text-xs">{{ shortRef(row.original.ref) }}</code></template>
        <template #pr-cell="{ row }">{{ row.original.pr ? `#${row.original.pr}` : "—" }}</template>
        <template #sha-cell="{ row }"><code class="text-xs">{{ shortSha(row.original.sha) }}</code></template>
        <template #created_ms-cell="{ row }"><RelTime :ms="row.original.created_ms" /></template>
      </UTable>
      <div class="flex gap-2">
        <UButton v-if="route.query.before" color="neutral" variant="outline" icon="i-lucide-arrow-up-to-line" label="Newest" :to="{ query: { ...route.query, before: undefined } }" />
        <UButton v-if="page?.next" color="neutral" variant="outline" trailing-icon="i-lucide-arrow-right" label="Older runs" :to="{ query: { ...route.query, repo: repo ?? undefined, before: page.next } }" />
      </div>
    </template>
  </SPage>
</template>
