<script setup lang="ts">
// A tenant's administration: members and roles, repositories and access,
// service accounts and their credentials, secret metadata (never values),
// storage and retention, and the run control audit.
const route = useRoute();
const slug = route.params.slug as string;
const section = computed(() => (route.params.section as string) || "members");
const tabs = computed(() => [
  { label: "Members", icon: "i-lucide-users", to: `/t/${slug}/admin/members`, active: section.value === "members" },
  { label: "Repositories", icon: "i-lucide-folder-git-2", to: `/t/${slug}/admin/repos`, active: section.value === "repos" },
  { label: "Service accounts", icon: "i-lucide-bot", to: `/t/${slug}/admin/service-accounts`, active: section.value === "service-accounts" },
  { label: "Secrets", icon: "i-lucide-key-round", to: `/t/${slug}/admin/secrets`, active: section.value === "secrets" },
  { label: "Storage", icon: "i-lucide-hard-drive", to: `/t/${slug}/admin/storage`, active: section.value === "storage" },
  { label: "Audit", icon: "i-lucide-scroll-text", to: `/t/${slug}/admin/audit`, active: section.value === "audit" },
]);
useHead({ title: `Tenant admin · ${slug} · Sentinel` });
const { needed: override, reason } = useOverride(() => slug);
</script>

<template>
  <SPage id="tenant-admin" :title="`Tenant admin · ${slug}`">
    <template #toolbar>
      <UDashboardToolbar>
        <UNavigationMenu :items="tabs" highlight class="-mx-1 flex-1" aria-label="Sections" />
      </UDashboardToolbar>
    </template>
    <section v-if="override && ['members', 'repos', 'service-accounts'].includes(section)" aria-labelledby="override-h" class="space-y-3 rounded-lg border border-warning/40 bg-warning/5 p-4">
      <h2 id="override-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-shield-alert" class="text-warning" />Acting as platform administrator</h2>
      <p class="text-sm">You do not administer this tenant. Changes to members, repository access and service accounts ask for a second factor and the reason below, which the audit records.</p>
      <UFormField label="Reason" name="override-reason" hint="1 to 100 characters">
        <UInput id="override-reason" v-model="reason" maxlength="100" autocomplete="off" class="w-full sm:w-96" />
      </UFormField>
    </section>
    <AdminMembers v-if="section === 'members'" :slug="slug" />
    <AdminRepos v-else-if="section === 'repos'" :slug="slug" />
    <AdminServiceAccounts v-else-if="section === 'service-accounts'" :slug="slug" />
    <AdminSecrets v-else-if="section === 'secrets'" :slug="slug" />
    <AdminStorage v-else-if="section === 'storage'" :slug="slug" />
    <AdminAudit v-else :slug="slug" />
  </SPage>
</template>
