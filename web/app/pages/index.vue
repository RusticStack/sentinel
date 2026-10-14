<script setup lang="ts">
// Home: the last tenant used (remembered in a cookie so the server can
// redirect before drawing anything), else the first one. A round trip that
// left the interface (GitHub sign-in, linking GitHub) ends here with a full
// page load; its pending return, a cookie, wins over the tenant on the
// server-side render as well as in the browser.
const session = useSession();
const last = useCookie<string | null>("sentinel-tenant", { sameSite: "lax", maxAge: 60 * 60 * 24 * 365 });
const back = useCookie<string | null>(RETURN_COOKIE, { sameSite: "lax", path: "/", maxAge: RETURN_SECONDS });
const dest = sameOriginPath(back.value);
if (back.value != null) back.value = null;
const target = session.tenants.value.find((t) => t.slug === last.value) ?? session.tenants.value[0];
if (dest !== "/") await navigateTo(dest, { replace: true });
else if (target) await navigateTo(`/t/${target.slug}`, { replace: true });
useHead({ title: "Sentinel" });
</script>

<template>
  <SPage id="home" title="Sentinel">
    <UEmpty
      icon="i-lucide-building-2"
      title="No organizations yet"
      description="Your account does not belong to any organization yet. Accept an invitation from your email, create an organization if this instance allows it, or link GitHub to join one whose membership GitHub manages."
      :actions="[
        { label: 'Organizations', to: '/organizations', icon: 'i-lucide-building' },
        ...(session.me.value?.super_admin ? [{ label: 'Open platform administration', to: '/platform', icon: 'i-lucide-shield', color: 'neutral' as const, variant: 'outline' as const }] : []),
      ]"
    />
  </SPage>
</template>
