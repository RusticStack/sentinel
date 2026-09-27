<script setup lang="ts">
const props = defineProps<{ slug: string }>();
const api = useApi();
const act = useAct();
const { data, refresh } = await useRepos(() => props.slug);
const name = ref("");
const sources = ref<Record<string, any>>({});
const grants = reactive<Record<string, { who: string; access: string[] }>>({});
const ACCESS = [{ label: "Read", value: "read" }, { label: "Run", value: "run" }, { label: "Secrets", value: "secrets" }];

async function create() {
  if (await act(`Create ${name.value}`, () => api(`/api/v1/tenants/${props.slug}/repos`, { method: "POST", body: { name: name.value } }))) {
    name.value = "";
    await refresh();
  }
}
async function source(repo: string) {
  if (sources.value[repo]) { delete sources.value[repo]; return; }
  const s = await act(`Source of ${repo}`, () => api(`/api/v1/tenants/${props.slug}/repos/${encodeURIComponent(repo)}/source`));
  if (s) sources.value[repo] = s;
}
function grantOf(id: string) { return (grants[id] ||= { who: "", access: ["read"] }); }
async function grant(repo: { id: string; name: string }) {
  const g = grantOf(repo.id);
  await act(`Access to ${repo.name}`, () => api(`/api/v1/tenants/${props.slug}/repos/${encodeURIComponent(repo.name)}/grants/${encodeURIComponent(g.who)}`, { method: "PUT", body: { access: g.access } }));
}
</script>

<template>
  <section aria-labelledby="repos-h" class="space-y-3">
    <h2 id="repos-h" class="text-base font-semibold">Repositories</h2>
    <p class="text-sm text-muted">Source bindings, deploy credentials and hook secrets are set on the controller host (<code>sentinel admin source …</code>); credentials never cross the API.</p>
    <div class="grid gap-3 md:grid-cols-2">
      <UCard v-for="repo in data?.repos ?? []" :key="repo.id" :ui="{ body: 'space-y-3' }">
        <template #header>
          <div class="flex items-center justify-between gap-2">
            <h3 class="font-semibold flex items-center gap-2"><UIcon name="i-lucide-folder-git-2" />{{ repo.name }}</h3>
            <UButton size="sm" color="neutral" variant="outline" :aria-expanded="!!sources[repo.name]" label="Source binding" @click="source(repo.name)" />
          </div>
        </template>
        <dl v-if="sources[repo.name]?.bound" class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
          <dt class="text-muted">Remote</dt><dd><code class="text-xs break-all">{{ sources[repo.name].remote }}</code></dd>
          <dt class="text-muted">Allowed refs</dt><dd><code class="text-xs">{{ sources[repo.name].allowed_refs.join(", ") || "—" }}</code></dd>
          <dt class="text-muted">Pipeline</dt><dd><code class="text-xs">{{ sources[repo.name].pipeline_path }}</code></dd>
          <dt class="text-muted">Trust pinned</dt><dd>{{ sources[repo.name].trust_pinned ? "yes" : "no" }}</dd>
          <dt class="text-muted">Version</dt><dd>{{ sources[repo.name].version }}<template v-if="sources[repo.name].revoked"> (revoked)</template></dd>
        </dl>
        <p v-else-if="sources[repo.name]" class="text-sm text-muted">No source binding yet.</p>
        <form class="flex flex-wrap items-end gap-2" :aria-label="`Grant access to ${repo.name}`" @submit.prevent="grant(repo)">
          <UFormField label="Member" :name="`g-${repo.id}`"><UInput :id="`g-${repo.id}`" v-model="grantOf(repo.id).who" required class="w-40" /></UFormField>
          <UFormField label="Access" :name="`a-${repo.id}`">
            <UCheckboxGroup v-model="grantOf(repo.id).access" :items="ACCESS" orientation="horizontal" />
          </UFormField>
          <UButton type="submit" size="sm" label="Set access" />
        </form>
      </UCard>
    </div>
  </section>
  <section aria-labelledby="new-repo-h" class="space-y-3">
    <h2 id="new-repo-h" class="text-base font-semibold">Add a repository</h2>
    <form class="flex flex-wrap items-end gap-3" aria-label="Add a repository" @submit.prevent="create">
      <UFormField label="Name" name="name"><UInput id="r-name" v-model="name" required pattern="[A-Za-z0-9._\-]{1,128}" class="w-56" /></UFormField>
      <UButton type="submit" icon="i-lucide-plus" label="Create" />
    </form>
  </section>
</template>
