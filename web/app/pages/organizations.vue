<script setup lang="ts">
import type { Security, TenantChoice } from "~~/shared/types/api";

// Every namespace the person belongs to, kept in three groups: their own
// personal namespace, organizations managed in Sentinel, and organizations
// whose membership GitHub manages. Creating an organization (when the
// deployment allows it), and what joining a GitHub-managed one takes.
// Nothing here lists a namespace the person is not a member of.
useHead({ title: "Organizations · Sentinel" });
const api = useApi();
const session = useSession();

const { data: security, status: securityStatus } = await useAsyncData("orgs-security", () => api<Security>("/api/v1/me/security").catch(() => null));
const githubLinked = computed(() => !!security.value?.identities.some((i) => i.provider === "github"));

const ROLE_NAMES: Record<string, string> = { reader: "Reader", operator: "Operator", admin: "Admin" };
const GROUPS = [
  { key: "personal", title: "Personal", icon: "i-lucide-user", note: "Your own space. Only you are a member." },
  { key: "app", title: "Organizations", icon: "i-lucide-building-2", note: "Membership is managed in Sentinel: by invitation, by an administrator, or by the operator's email-domain rule." },
  { key: "github", title: "GitHub organizations", icon: "i-lucide-github", note: "Membership is managed by GitHub: Sentinel follows who belongs to the GitHub organization." },
] as const;
const groups = computed(() => {
  const by: Record<"personal" | "app" | "github", TenantChoice[]> = { personal: [], app: [], github: [] };
  for (const t of session.tenants.value) by[t.kind === "personal" ? "personal" : t.membership === "github" ? "github" : "app"].push(t);
  return by;
});

const visibleGroups = computed(() => GROUPS.filter((g) => groups.value[g.key].length));

const refreshing = ref(false);
async function refreshList() {
  refreshing.value = true;
  try { await session.refreshTenants(); } finally { refreshing.value = false; }
}


const slug = ref("");
const touched = ref(false);
const creating = ref(false);
const createError = ref("");
const notAllowed = ref(false);
const { waiting, start: wait } = useRetryWait();
const shapeProblem = computed(() => (touched.value && slug.value ? slugProblem(slug.value) : null));
const slugInput = useTemplateRef<{ inputRef?: HTMLInputElement }>("slugInput");

async function create() {
  touched.value = true;
  createError.value = "";
  notAllowed.value = false;
  const name = slug.value.trim();
  const problem = slugProblem(name);
  if (problem) {
    createError.value = problem;
    nextTick(() => slugInput.value?.inputRef?.focus());
    return;
  }
  if (creating.value || waiting.value) return;
  creating.value = true;
  try {
    await api<{ slug: string }>("/api/v1/orgs", { method: "POST", body: { slug: name } });
    slug.value = "";
    touched.value = false;
    await session.refreshTenants();
    useState("tenant").value = name;
    await navigateTo(`/t/${name}/settings`);
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    if (err.code === "forbidden") notAllowed.value = true;
    else if (err.code === "conflict") createError.value = "That name is taken. Choose another.";
    else if (err.code === "invalid_request") createError.value = "That name is reserved or not allowed. Choose another.";
    else if (err.code === "quota_exceeded") createError.value = "You have created as many organizations as allowed for now (3 an hour, 10 in all). Try later or ask an administrator.";
    else if (err.code === "rate_limited") {
      wait(err);
      createError.value = `Too many attempts. Try again in ${retryAfter(err)}.`;
    } else createError.value = refusal(err);
    nextTick(() => slugInput.value?.inputRef?.focus());
  } finally {
    creating.value = false;
  }
}
</script>

<template>
  <SPage id="organizations" title="Organizations">
    <div class="max-w-3xl space-y-6">
      <section aria-labelledby="ns-h" class="space-y-4">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h2 id="ns-h" class="text-base font-semibold">Your namespaces</h2>
          <UButton size="sm" color="neutral" variant="ghost" icon="i-lucide-refresh-cw" label="Refresh" :loading="refreshing" @click="refreshList" />
        </div>
        <UEmpty v-if="!session.tenants.value.length" icon="i-lucide-building-2" title="No namespaces yet"
          description="You are not a member of any organization yet. Accept an invitation, create an organization below if this instance allows it, or ask an administrator to add you." />

        <div v-for="g in visibleGroups" :key="g.key" class="space-y-2">
          <h3 class="text-sm font-medium flex items-center gap-2"><UIcon :name="g.icon" />{{ g.title }}</h3>
          <p class="text-xs text-muted">{{ g.note }}</p>
          <ul class="divide-y divide-default rounded-lg border border-default">
            <li v-for="t in groups[g.key]" :key="t.slug" class="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
              <span class="flex items-center gap-2 min-w-0">
                <ULink :to="`/t/${t.slug}`" class="font-medium truncate">{{ t.slug }}</ULink>
                <UBadge color="neutral" variant="outline" size="sm" :label="ROLE_NAMES[t.role] ?? t.role" />
                <UBadge v-if="g.key === 'github'" color="neutral" variant="subtle" size="sm" icon="i-lucide-github" label="Managed by GitHub" />
              </span>
              <UButton :to="`/t/${t.slug}/settings`" size="sm" color="neutral" variant="ghost" icon="i-lucide-settings" :aria-label="`Settings of ${t.slug}`" label="Settings" />
            </li>
          </ul>
        </div>
      </section>

      <!-- Joining an organization whose membership GitHub manages. -->
      <UCard as="section" aria-labelledby="gh-h">
        <template #header>
          <h2 id="gh-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-github" />Organizations on GitHub</h2>
        </template>
        <USkeleton v-if="securityStatus === 'pending'" class="h-10 w-full" />
        <div v-else-if="!githubLinked" class="space-y-3 text-sm">
          <p>Some organizations here take their members from GitHub. To join one, link the GitHub account that belongs to that GitHub organization; Sentinel then asks GitHub, and the organization appears here once GitHub confirms you are a member. Email invitations and email domains never add anyone to these organizations.</p>
          <UButton v-if="security?.github_link" to="/account" icon="i-lucide-github" color="neutral" variant="outline" label="Connect GitHub to join" />
          <p v-else class="text-muted">This instance does not offer GitHub linking.</p>
        </div>
        <div v-else class="space-y-2 text-sm">
          <p>Your GitHub account is linked. Organizations whose membership GitHub manages appear here once GitHub confirms you belong to them. Sentinel asks at every sign-in, when GitHub reports a change, and periodically; if you just joined on GitHub, refresh this list in a minute.</p>
          <p class="text-muted">Leaving the organization on GitHub removes your access to that organization only.</p>
        </div>
      </UCard>

      <!-- Create an organization. -->
      <UCard as="section" aria-labelledby="new-org-h">
        <template #header>
          <h2 id="new-org-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-plus" />Create an organization</h2>
        </template>
        <form class="space-y-3" aria-label="Create an organization" novalidate @submit.prevent="create">
          <p class="text-sm">You become its administrator and invite people by email. Whether you may create one is this instance's policy.</p>
          <UFormField label="Name" name="slug" hint="Lowercase letters, digits and hyphens" :error="shapeProblem ?? undefined">
            <UInput id="org-slug" ref="slugInput" v-model="slug" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="63" placeholder="my-team" class="w-full sm:w-80" @blur="touched = true" />
          </UFormField>
          <UAlert v-if="createError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="createError" role="alert" />
          <UAlert v-if="notAllowed" color="warning" variant="subtle" icon="i-lucide-lock" role="alert" title="Creating organizations is not enabled for your account."
            :description="session.me.value?.super_admin ? 'Platform administrators always may; check that this session is yours.' : 'An administrator can create one for you and invite you, or allow approved users to create their own.'" />
          <UButton type="submit" icon="i-lucide-building-2" :label="waiting ? `Wait ${waiting} s` : 'Create organization'" :loading="creating" :disabled="!!waiting" />
        </form>
      </UCard>
    </div>
  </SPage>
</template>
