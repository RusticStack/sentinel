<script setup lang="ts">
// A namespace's settings, read-only: what kind it is, where its membership
// comes from, the caller's own standing with GitHub in a GitHub-managed
// organization (with a re-check), and — for an administrator — which email
// domains the operator set to join it automatically. Nothing here is
// editable: the membership source is an explicit administrator act, and the
// domain rule is the operator's environment variable.
const route = useRoute();
const slug = route.params.slug as string;
useHead({ title: `Settings · ${slug} · Sentinel` });
const api = useApi();
const session = useSession();

const { data: loaded, refresh, status } = await useNamespaceSettings(slug);
const data = computed(() => loaded.value?.settings ?? null);
const failure = computed(() => loaded.value?.failure ?? null);
if (import.meta.client) watch(failure, (f) => { if (f?.code === "not_found") session.refreshTenants(); }, { immediate: true });

const ROLE_NAMES: Record<string, string> = { reader: "Reader", operator: "Operator", admin: "Admin" };
const isAdmin = computed(() => data.value?.role === "admin" || !!session.me.value?.super_admin);
const githubManaged = computed(() => data.value?.membership === "github");
// An organization with a bound GitHub App installation takes no email
// invitations even before it is GitHub-managed.
const invitesApply = computed(() => data.value?.kind === "organization" && !githubManaged.value && !data.value?.github_installation);
const where = computed(() => githubStanding(data.value?.github_sync));
const isoDate = (ms: number) => new Date(ms).toISOString().slice(0, 10);

// Opening the namespace's repositories asks Sentinel to check the caller
// with GitHub when the last confirmation is older than five minutes (at
// most once a minute); the answer arrives in the background.
const rechecking = ref(false);
const recheckNote = ref("");
const { waiting, start: hold } = useRetryWait();
async function recheck() {
  if (rechecking.value || waiting.value) return;
  rechecking.value = true;
  recheckNote.value = "";
  try {
    await api(`/api/v1/tenants/${slug}/repos`);
    hold(60_000);
    await new Promise((r) => setTimeout(r, 3000));
    await refresh();
    await session.refreshTenants();
    recheckNote.value = "Sentinel asked GitHub again if your access had not been confirmed in the last five minutes. GitHub answers in the background; this page shows the latest answer.";
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    if (err.code === "not_found") {
      recheckNote.value = "You no longer have access to this organization.";
      await session.refreshTenants();
    } else if (err.code === "rate_limited") {
      hold(err);
      recheckNote.value = `Sentinel is busy. Try again in ${retryAfter(err)}.`;
    } else recheckNote.value = refusal(err);
  } finally {
    rechecking.value = false;
  }
}
</script>

<template>
  <SPage id="namespace-settings" :title="`Settings · ${slug}`">
    <div class="max-w-3xl space-y-6">
      <UAlert v-if="failure" color="error" variant="subtle" icon="i-lucide-circle-alert" role="alert"
        :title="failure.code === 'not_found' ? 'Not found, or you no longer have access to it.' : 'Could not load the settings.'"
        :description="failure.code === 'not_found' ? undefined : failure.words"
        :actions="failure.code === 'not_found' ? [{ label: 'Your organizations', to: '/organizations' }] : [{ label: 'Try again', onClick: () => { refresh(); } }]" />

      <USkeleton v-else-if="status === 'pending' && !data" class="h-40 w-full" />

      <template v-else-if="data">
        <!-- What it is -->
        <UCard as="section" aria-labelledby="about-h">
          <template #header>
            <h2 id="about-h" class="text-base font-semibold flex items-center gap-2"><UIcon :name="data.kind === 'personal' ? 'i-lucide-user' : githubManaged ? 'i-lucide-github' : 'i-lucide-building-2'" />About</h2>
          </template>
          <dl class="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-[max-content_1fr]">
            <dt class="text-muted">Kind</dt>
            <dd>{{ data.kind === "personal" ? "Personal namespace" : "Organization" }}</dd>
            <dt class="text-muted">Membership</dt>
            <dd class="flex flex-wrap items-center gap-2">
              <UBadge v-if="githubManaged" color="neutral" variant="subtle" icon="i-lucide-github" label="Managed by GitHub" />
              <UBadge v-else color="neutral" variant="outline" :label="data.kind === 'personal' ? 'Only you' : 'Managed in Sentinel'" />
            </dd>
            <dt class="text-muted">Your role</dt>
            <dd>{{ data.role ? ROLE_NAMES[data.role] : "Not a member (platform administrator)" }}</dd>
            <dt class="text-muted">GitHub App</dt>
            <dd>{{ data.github_installation ? "Installed for this namespace" : "Not installed" }}</dd>
            <dt class="text-muted">Created</dt>
            <dd><time :datetime="new Date(data.created_ms).toISOString()">{{ isoDate(data.created_ms) }}</time></dd>
          </dl>
        </UCard>

        <!-- Who belongs -->
        <UCard as="section" aria-labelledby="members-h">
          <template #header>
            <h2 id="members-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-users" />Who belongs here</h2>
          </template>

          <div v-if="data.kind === 'personal'" class="space-y-2 text-sm">
            <p>This is your personal namespace: only you belong to it, and nobody can be invited. To work with others, <ULink to="/organizations" class="font-medium text-primary">create an organization</ULink>.</p>
          </div>

          <div v-else-if="githubManaged" class="space-y-4 text-sm">
            <p>Membership is managed by GitHub. Sentinel follows who belongs to the GitHub organization: its owners are administrators here and other members operators, and each repository's access follows the person's permission on that repository on GitHub. Invitations and email domains do not add anyone; people are added and removed on GitHub.</p>

            <div v-if="data.role" class="space-y-3 rounded-md border border-default p-3" role="status" aria-live="polite">
              <h3 class="font-medium">Your access</h3>
              <p v-if="where === 'confirmed'" class="flex items-start gap-2"><UIcon name="i-lucide-circle-check" class="mt-0.5 shrink-0 text-success" />
                <span>GitHub confirmed your membership <RelTime :ms="data.github_sync?.confirmed_ms" />.</span></p>
              <p v-else-if="where === 'checking'" class="flex items-start gap-2"><UIcon name="i-lucide-loader-circle" class="mt-0.5 shrink-0 text-info" />
                <span>A check with GitHub is waiting to run<template v-if="data.github_sync?.confirmed_ms">; it last confirmed you <RelTime :ms="data.github_sync.confirmed_ms" /></template>.</span></p>
              <UAlert v-else-if="where === 'unknown'" color="warning" variant="subtle" icon="i-lucide-cloud-off" title="GitHub could not confirm your access recently."
                :description="`GitHub did not answer the last ${data.github_sync?.unanswered === 1 ? 'check' : `${data.github_sync?.unanswered} checks`} (it may be unreachable, rate-limited, or missing a permission). Your existing access is kept for a limited grace period (one day unless the operator changed it) and nothing new is granted until GitHub answers; Sentinel keeps retrying.`" />
              <p v-else class="flex items-start gap-2"><UIcon name="i-lucide-circle-dashed" class="mt-0.5 shrink-0 text-muted" />
                <span>GitHub has not confirmed your membership yet.</span></p>
              <div class="flex flex-wrap items-center gap-3">
                <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-refresh-cw" :label="waiting ? `Re-check again in ${waiting} s` : 'Re-check access'" :loading="rechecking" :disabled="!!waiting" @click="recheck" />
                <span class="text-xs text-muted">Sentinel also checks at every sign-in and periodically.</span>
              </div>
              <p v-if="recheckNote" class="text-xs">{{ recheckNote }}</p>
            </div>
          </div>

          <div v-else class="space-y-3 text-sm">
            <p v-if="invitesApply">Membership is managed in Sentinel: people join by email invitation, when an administrator adds them, or through an email domain the operator set (below).</p>
            <p v-else>Membership is managed in Sentinel by administrators. A GitHub App is installed for this organization, so email invitations and email domains do not apply to it.</p>
            <div v-if="isAdmin" class="flex flex-wrap gap-2">
              <UButton :to="`/t/${slug}/admin/members`" size="sm" color="neutral" variant="outline" icon="i-lucide-users" label="Members" />
              <UButton v-if="invitesApply" :to="`/t/${slug}/admin/invitations`" size="sm" color="neutral" variant="outline" icon="i-lucide-mail-plus" label="Invite people" />
            </div>
            <p v-else class="text-muted">Ask an administrator of {{ slug }} to invite someone.</p>
          </div>
        </UCard>

        <!-- The operator's domain rule (administrators only; never editable) -->
        <UCard v-if="data.auto_join" as="section" aria-labelledby="domains-h">
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-2">
              <h2 id="domains-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-at-sign" />Email domains that join automatically</h2>
              <UBadge color="neutral" variant="outline" icon="i-lucide-lock" label="Read-only" />
            </div>
          </template>
          <div class="space-y-3 text-sm">
            <template v-if="data.auto_join.domains.length">
              <ul class="flex flex-wrap gap-2" aria-label="Domains">
                <li v-for="d in data.auto_join.domains" :key="d"><UBadge color="neutral" variant="subtle" size="lg" class="font-mono" :label="d" /></li>
              </ul>
              <p v-if="data.auto_join.applies">A person whose confirmed email address is at exactly one of these domains (not a subdomain) joins this organization as a Reader when the address is confirmed or at their next sign-in. Removing a domain stops new joins; nobody who joined is removed.</p>
              <p v-else>These domains are listed for this namespace but do not apply: domain joining never adds anyone to a personal namespace or to an organization with a GitHub App or GitHub-managed membership.</p>
            </template>
            <p v-else>No email domain joins this organization automatically.</p>
            <p class="text-xs text-muted">Set by the server's operator (<code>SENTINEL_AUTO_JOIN_DOMAINS</code>), not here.</p>
          </div>
        </UCard>
      </template>
    </div>
  </SPage>
</template>
