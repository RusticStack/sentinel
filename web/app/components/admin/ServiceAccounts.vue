<script setup lang="ts">
import type { Grant, Member } from "~~/shared/types/api";
import ShowOnceModal from "~/components/ShowOnceModal.vue";

// Service accounts (O06): principals confined to this tenant that never sign
// in. Creating one, giving it repository access and issuing it a credential
// are step-up changes for everyone (the dialog asks, then the change is
// retried); the refresh token is shown once and never again.
const props = defineProps<{ slug: string }>();
const api = useApi();
const act = useAct();
const { ready, withReason } = useOverride(() => props.slug);
const showOnce = useOverlay().create(ShowOnceModal, { destroyOnClose: true });

const { data, refresh } = await useAsyncData(`service-accounts-${props.slug}`, async () => {
  const page = await api<{ members: Member[]; next: string | null }>(`/api/v1/tenants/${props.slug}/members?limit=100`);
  return { accounts: page.members.filter((m) => m.kind === "service"), partial: !!page.next };
});
const { data: repos } = await useRepos(() => props.slug);
const repoItems = computed(() => (repos.value?.repos ?? []).map((r) => ({ label: r.name, value: r.name })));
const repoName = (id: string | null) => (id ? repos.value?.repos.find((r) => r.id === id)?.name ?? shortId(id) : "every repository it may use");

const ROLES = [{ label: "Operator (runs)", value: "operator" }, { label: "Reader", value: "reader" }];
const ACCESS = [{ label: "Read", value: "read" }, { label: "Run", value: "run" }];
const SCOPES = ["runs:read", "runs:write", "logs:read", "artifacts:read", "cache:read", "cache:write", "secrets:metadata", "secrets:write"]
  .map((s) => ({ label: s, value: s }));
const HOUR = 3600e3;
const LIFETIMES = [
  { label: "1 hour", value: HOUR }, { label: "1 day", value: 24 * HOUR }, { label: "7 days", value: 7 * 24 * HOUR },
  { label: "30 days", value: 30 * 24 * HOUR }, { label: "90 days", value: 90 * 24 * HOUR },
];
const ANY_REPO = "__any__";

const name = ref("");
const role = ref("operator");
async function create() {
  if (!ready()) return;
  const body = withReason({ name: name.value.trim(), role: role.value });
  if (await act(`Create ${body.name}`, () => api(`/api/v1/tenants/${props.slug}/service-accounts`, { method: "POST", body }))) {
    name.value = "";
    await refresh();
  }
}

// Per account: the repository-access form, the issue form and the listed grants.
const access = reactive<Record<string, { repo: string; access: string[] }>>({});
const issue = reactive<Record<string, { name: string; scope: string[]; repo: string; lifetime: number }>>({});
const grants = reactive<Record<string, Grant[] | undefined>>({});
const accessOf = (u: string) => (access[u] ||= { repo: repoItems.value[0]?.value ?? "", access: ["read", "run"] });
const issueOf = (u: string) => (issue[u] ||= { name: "", scope: ["runs:read", "runs:write", "logs:read"], repo: ANY_REPO, lifetime: 30 * 24 * HOUR });

async function setAccess(m: Member) {
  const a = accessOf(m.user);
  if (!a.repo || !ready()) return;
  await act(`Access of ${m.display_name} to ${a.repo}`, () => api(`/api/v1/tenants/${props.slug}/service-accounts/${m.user}/repos/${encodeURIComponent(a.repo)}`, { method: "PUT", body: withReason({ access: a.access }) }));
}

async function loadGrants(m: Member) {
  const list = await act(`Credentials of ${m.display_name}`, () => api<{ grants: Grant[] }>(`/api/v1/tenants/${props.slug}/service-accounts/${m.user}/grants`));
  if (list) grants[m.user] = list.grants;
}
async function toggleGrants(m: Member) {
  if (grants[m.user]) delete grants[m.user];
  else await loadGrants(m);
}

async function issueGrant(m: Member) {
  const f = issueOf(m.user);
  if (!f.scope.length || !ready()) return;
  const body = withReason({
    name: f.name.trim(),
    scope: f.scope.join(" "),
    expires_in_ms: f.lifetime,
    ...(f.repo === ANY_REPO ? {} : { repo: f.repo }),
  });
  const issued = await act(`Credential ${body.name} for ${m.display_name}`, () =>
    api<{ grant: string; refresh_token: string; expires_ms: number }>(`/api/v1/tenants/${props.slug}/service-accounts/${m.user}/grants`, { method: "POST", body }));
  if (!issued) return;
  f.name = "";
  await showOnce.open({
    title: `Credential for ${m.display_name}`,
    description: `A refresh token for ${body.scope}, valid until ${new Date(issued.expires_ms).toISOString().slice(0, 10)}. It is shown this once.`,
    secrets: [issued.refresh_token],
    filename: `${m.display_name.replace(/[^A-Za-z0-9._-]+/g, "-")}.token`,
    note: "On the agent's machine: sentinel auth login --grant-file <file>. Importing spends it, so the file can be deleted afterwards.",
  });
  if (grants[m.user]) await loadGrants(m);
}

const revoking = ref<{ account: Member; grant: Grant } | null>(null);
async function revoke() {
  const r = revoking.value;
  revoking.value = null;
  if (!r) return;
  if (await act(`Revoke ${r.grant.name ?? shortId(r.grant.id)}`, () => api(`/api/v1/grants/${r.grant.id}`, { method: "DELETE" }))) await loadGrants(r.account);
}
const grantColumns = [
  { id: "name", header: "Name" }, { accessorKey: "scope", header: "Scope" }, { id: "repo", header: "Repository" },
  { id: "expires", header: "Expires" }, { id: "used", header: "Last used" }, { id: "actions", header: "Actions" },
];
</script>

<template>
  <section aria-labelledby="sa-h" class="space-y-3">
    <h2 id="sa-h" class="text-base font-semibold">Service accounts</h2>
    <p class="text-sm text-muted">Automation that runs pipelines or reads results without a person's account. Each credential is a refresh token the agent imports; it lasts until it expires or is revoked.</p>
    <UEmpty v-if="!data?.accounts.length" icon="i-lucide-bot" title="No service accounts yet" description="Create one below, give it access to a repository, then issue it a credential." />
    <div v-else class="grid gap-3 lg:grid-cols-2">
      <UCard v-for="m in data.accounts" :key="m.user" :ui="{ body: 'space-y-4' }">
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 class="font-semibold flex items-center gap-2"><UIcon name="i-lucide-bot" />{{ m.display_name }}</h3>
              <p class="text-xs text-muted font-mono">{{ shortId(m.user) }}</p>
            </div>
            <div class="flex gap-2">
              <UBadge color="neutral" variant="outline" :label="m.role" />
              <UBadge v-if="!m.active" color="warning" variant="subtle" label="inactive" />
            </div>
          </div>
        </template>

        <form class="flex flex-wrap items-end gap-2" :aria-label="`Repository access of ${m.display_name}`" @submit.prevent="setAccess(m)">
          <UFormField label="Repository" :name="`sa-repo-${m.user}`">
            <USelect :id="`sa-repo-${m.user}`" v-model="accessOf(m.user).repo" :items="repoItems" placeholder="No repositories" class="w-44" />
          </UFormField>
          <UFormField label="Access" :name="`sa-access-${m.user}`">
            <UCheckboxGroup v-model="accessOf(m.user).access" :items="ACCESS" orientation="horizontal" />
          </UFormField>
          <UButton type="submit" size="sm" label="Set access" :disabled="!repoItems.length" />
        </form>

        <form class="space-y-3 rounded-md border border-default p-3" :aria-label="`Issue a credential to ${m.display_name}`" @submit.prevent="issueGrant(m)">
          <h4 class="text-sm font-medium">Issue a credential</h4>
          <div class="flex flex-wrap items-end gap-2">
            <UFormField label="Name" :name="`sa-gname-${m.user}`">
              <UInput :id="`sa-gname-${m.user}`" v-model="issueOf(m.user).name" required maxlength="128" autocomplete="off" placeholder="ci-agent" class="w-40" />
            </UFormField>
            <UFormField label="Repository" :name="`sa-grepo-${m.user}`">
              <USelect :id="`sa-grepo-${m.user}`" v-model="issueOf(m.user).repo" :items="[{ label: 'Any it may use', value: ANY_REPO }, ...repoItems]" class="w-44" />
            </UFormField>
            <UFormField label="Valid for" :name="`sa-life-${m.user}`">
              <USelect :id="`sa-life-${m.user}`" v-model="issueOf(m.user).lifetime" :items="LIFETIMES" class="w-32" />
            </UFormField>
          </div>
          <UFormField label="Scopes" :name="`sa-scope-${m.user}`" :error="issueOf(m.user).scope.length ? undefined : 'Choose at least one scope.'">
            <UCheckboxGroup v-model="issueOf(m.user).scope" :items="SCOPES" orientation="horizontal" :ui="{ fieldset: 'flex-wrap gap-x-4 gap-y-1' }" />
          </UFormField>
          <UButton type="submit" size="sm" icon="i-lucide-key-round" label="Issue" :disabled="!issueOf(m.user).scope.length" />
        </form>

        <div class="space-y-2">
          <UButton size="sm" color="neutral" variant="outline" :aria-expanded="!!grants[m.user]" :label="grants[m.user] ? 'Hide credentials' : 'Show credentials'" @click="toggleGrants(m)" />
          <template v-if="grants[m.user]">
            <p v-if="!grants[m.user]!.length" class="text-sm text-muted">No credentials issued.</p>
            <UTable v-else :data="grants[m.user]" :columns="grantColumns" :caption="`Credentials of ${m.display_name}`" class="rounded-lg border border-default">
              <template #name-cell="{ row }">
                <span class="font-medium">{{ row.original.name ?? "—" }}</span>
                <UBadge v-if="row.original.revoked" color="neutral" variant="subtle" label="revoked" size="sm" class="ms-1" />
              </template>
              <template #repo-cell="{ row }">{{ repoName(row.original.repo) }}</template>
              <template #expires-cell="{ row }"><time :datetime="new Date(row.original.expires_ms).toISOString()">{{ new Date(row.original.expires_ms).toISOString().slice(0, 10) }}</time></template>
              <template #used-cell="{ row }"><RelTime :ms="row.original.last_used_ms" /></template>
              <template #actions-cell="{ row }">
                <UButton v-if="!row.original.revoked" size="sm" color="error" variant="ghost" icon="i-lucide-ban" :aria-label="`Revoke ${row.original.name ?? row.original.id}`" label="Revoke"
                  @click="revoking = { account: m, grant: row.original }" />
              </template>
            </UTable>
          </template>
        </div>
      </UCard>
    </div>
    <p v-if="data?.partial" class="text-sm text-muted">Only service accounts among the first 100 members are shown.</p>
  </section>

  <section aria-labelledby="sa-new-h" class="space-y-3">
    <h2 id="sa-new-h" class="text-base font-semibold">Create a service account</h2>
    <form class="flex flex-wrap items-end gap-3" aria-label="Create a service account" @submit.prevent="create">
      <UFormField label="Name" name="sa-name"><UInput id="sa-name" v-model="name" required maxlength="128" autocomplete="off" class="w-56" /></UFormField>
      <UFormField label="Role" name="sa-role"><USelect id="sa-role" v-model="role" :items="ROLES" class="w-44" /></UFormField>
      <UButton type="submit" icon="i-lucide-plus" label="Create" />
    </form>
  </section>

  <UModal :open="!!revoking" :title="`Revoke ${revoking?.grant.name ?? 'this credential'}?`"
    description="Its access tokens stop working at once and its refresh token can no longer be used." @update:open="(o) => !o && (revoking = null)">
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="ghost" label="Keep" @click="revoking = null" />
        <UButton color="error" label="Revoke" @click="revoke" />
      </div>
    </template>
  </UModal>
</template>
