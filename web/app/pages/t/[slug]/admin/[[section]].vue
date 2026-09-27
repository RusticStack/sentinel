<script setup lang="ts">
// A tenant's administration: members and roles, repositories and access,
// secret metadata (never values), and the run control audit.
const route = useRoute();
const slug = route.params.slug as string;
const section = computed(() => (route.params.section as string) || "members");
const tabs = computed(() => [
  { label: "Members", icon: "i-lucide-users", to: `/t/${slug}/admin/members`, active: section.value === "members" },
  { label: "Repositories", icon: "i-lucide-folder-git-2", to: `/t/${slug}/admin/repos`, active: section.value === "repos" },
  { label: "Secrets", icon: "i-lucide-key-round", to: `/t/${slug}/admin/secrets`, active: section.value === "secrets" },
  { label: "Audit", icon: "i-lucide-scroll-text", to: `/t/${slug}/admin/audit`, active: section.value === "audit" },
]);
useHead({ title: `Tenant admin · ${slug} · Sentinel` });
</script>

<template>
  <SPage id="tenant-admin" :title="`Tenant admin · ${slug}`">
    <template #toolbar>
      <UDashboardToolbar>
        <UNavigationMenu :items="tabs" highlight class="-mx-1 flex-1" aria-label="Sections" />
      </UDashboardToolbar>
    </template>
    <AdminMembers v-if="section === 'members'" :slug="slug" />
    <AdminRepos v-else-if="section === 'repos'" :slug="slug" />
    <AdminSecrets v-else-if="section === 'secrets'" :slug="slug" />
    <AdminAudit v-else :slug="slug" />
  </SPage>
</template>
