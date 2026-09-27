<script setup lang="ts">
// Home: the last tenant used (remembered in a cookie so the server can
// redirect before drawing anything), else the first one.
const session = useSession();
const last = useCookie<string | null>("sentinel-tenant", { sameSite: "lax", maxAge: 60 * 60 * 24 * 365 });
if (import.meta.client) {
  // Back from GitHub sign-in: continue where the person was going.
  let back: string | null = null;
  try { back = sessionStorage.getItem("sentinel-return"); sessionStorage.removeItem("sentinel-return"); } catch { /* ignore */ }
  if (back && back.startsWith("/") && back !== "/") await navigateTo(back, { replace: true });
}
const target = session.tenants.value.find((t) => t.slug === last.value) ?? session.tenants.value[0];
if (target) await navigateTo(`/t/${target.slug}`, { replace: true });
useHead({ title: "Sentinel" });
</script>

<template>
  <SPage id="home" title="Sentinel">
    <UEmpty
      icon="i-lucide-building-2"
      title="No tenants yet"
      description="Your account is not a member of any tenant yet. An administrator can add you."
      :actions="session.me.value?.super_admin ? [{ label: 'Open platform administration', to: '/platform', icon: 'i-lucide-shield' }] : []"
    />
  </SPage>
</template>
