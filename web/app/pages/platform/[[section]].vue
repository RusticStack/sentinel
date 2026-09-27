<script setup lang="ts">
// Platform administration: registrations, tenants and their quotas,
// worker pools, admission policy and the audit trail. Suspension and
// policy changes need a fresh second factor (A06); the page asks for it
// when the controller does.
const route = useRoute();
const session = useSession();
if (!session.me.value?.super_admin) throw createError({ statusCode: 404, statusMessage: "Not found" });
const section = computed(() => (route.params.section as string) || "registrations");
const tabs = computed(() => [
  { label: "Registrations", icon: "i-lucide-user-check", to: "/platform/registrations", active: section.value === "registrations" },
  { label: "Tenants", icon: "i-lucide-building-2", to: "/platform/tenants", active: section.value === "tenants" },
  { label: "Pools", icon: "i-lucide-server", to: "/platform/pools", active: section.value === "pools" },
  { label: "Policy", icon: "i-lucide-scale", to: "/platform/policy", active: section.value === "policy" },
  { label: "Audit", icon: "i-lucide-scroll-text", to: "/platform/audit", active: section.value === "audit" },
]);
useHead({ title: "Platform · Sentinel" });
</script>

<template>
  <SPage id="platform" title="Platform">
    <template #toolbar>
      <UDashboardToolbar>
        <UNavigationMenu :items="tabs" highlight class="-mx-1 flex-1" aria-label="Sections" />
      </UDashboardToolbar>
    </template>
    <PlatformRegistrations v-if="section === 'registrations'" />
    <PlatformTenants v-else-if="section === 'tenants'" />
    <PlatformPools v-else-if="section === 'pools'" />
    <PlatformPolicy v-else-if="section === 'policy'" />
    <PlatformAudit v-else />
  </SPage>
</template>
