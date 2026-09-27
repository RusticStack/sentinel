<script setup lang="ts">
import type { DropdownMenuItem, NavigationMenuItem } from "@nuxt/ui";

const session = useSession();
const route = useRoute();
// The last tenant used (a cookie, so the server renders the same choice).
const remembered = useCookie<string | null>("sentinel-tenant", { sameSite: "lax", maxAge: 60 * 60 * 24 * 365 });
const tenant = useState<string | null>("tenant", () => remembered.value ?? null);
const colorMode = useColorMode();
// What views announce to screen readers (the log viewer's jumps, folds).
const announce = useState("announce", () => "");

// The tenant the pages act in: the route's, else the last one used.
const active = computed(() => (typeof route.params.slug === "string" ? route.params.slug : tenant.value));
const role = computed(() => session.roleIn(active.value ?? undefined));
const tenantItems = computed(() => session.tenants.value.map((t) => ({ label: t.slug, value: t.slug, description: t.role })));

function switchTenant(slug: string) {
  tenant.value = slug;
  navigateTo(`/t/${slug}`);
}

const links = computed<NavigationMenuItem[][]>(() => {
  const slug = active.value;
  const main: NavigationMenuItem[] = slug
    ? [
        { label: "Runs", icon: "i-lucide-play", to: `/t/${slug}`, exact: true },
        { label: "Queue", icon: "i-lucide-list-ordered", to: `/t/${slug}/queue` },
        { label: "Workers", icon: "i-lucide-server", to: `/t/${slug}/workers` },
        { label: "GitHub sync", icon: "i-lucide-refresh-cw", to: `/t/${slug}/sync` },
      ]
    : [];
  if (slug && (role.value === "admin" || session.me.value?.super_admin)) {
    main.push({ label: "Tenant admin", icon: "i-lucide-users", to: `/t/${slug}/admin` });
  }
  const platform: NavigationMenuItem[] = session.me.value?.super_admin
    ? [{ label: "Platform", icon: "i-lucide-shield", to: "/platform" }]
    : [];
  return [main, platform];
});

function skipToMain() {
  document.getElementById("main")?.focus();
}

const account = computed<DropdownMenuItem[][]>(() => [
  [{ label: session.me.value?.username || shortId(session.me.value?.user), type: "label", icon: "i-lucide-user" }],
  [
    {
      label: colorMode.value === "dark" ? "Light theme" : "Dark theme",
      icon: colorMode.value === "dark" ? "i-lucide-sun" : "i-lucide-moon",
      onSelect: () => { colorMode.preference = colorMode.value === "dark" ? "light" : "dark"; },
    },
    { label: "Sign out", icon: "i-lucide-log-out", onSelect: () => session.signOut() },
  ],
]);
</script>

<template>
  <UDashboardGroup unit="rem" storage="local">
    <a href="#main" @click.prevent="skipToMain" class="skip-link rounded-md bg-primary text-inverted px-3 py-2 text-sm font-medium">Skip to content</a>
    <UDashboardSidebar id="sentinel" collapsible resizable :default-size="16" :min-size="14" :max-size="22" :ui="{ footer: 'border-t border-default' }">
      <template #header="{ collapsed }">
        <NuxtLink to="/" class="flex items-center gap-2 font-semibold text-highlighted" aria-label="Sentinel home">
          <UIcon name="i-lucide-radar" class="size-5 text-primary" />
          <span v-if="!collapsed">Sentinel</span>
        </NuxtLink>
      </template>

      <template #default="{ collapsed }">
        <USelectMenu
          v-if="tenantItems.length && !collapsed"
          :model-value="active ?? undefined"
          :items="tenantItems"
          value-key="value"
          placeholder="Choose a tenant"
          icon="i-lucide-building-2"
          aria-label="Active tenant"
          class="w-full"
          @update:model-value="(v: string) => switchTenant(v)"
        />
        <UNavigationMenu :collapsed="collapsed" :items="links[0]" orientation="vertical" tooltip aria-label="Tenant" />
        <UNavigationMenu v-if="links[1]!.length" :collapsed="collapsed" :items="links[1]" orientation="vertical" tooltip class="mt-auto" aria-label="Platform" />
      </template>

      <template #footer="{ collapsed }">
        <UDropdownMenu :items="account" :content="{ align: 'center', collisionPadding: 12 }" :ui="{ content: collapsed ? 'w-48' : 'w-(--reka-dropdown-menu-trigger-width)' }">
          <UButton
            :label="collapsed ? undefined : (session.me.value?.username || 'Account')"
            icon="i-lucide-circle-user"
            color="neutral"
            variant="ghost"
            block
            :square="collapsed"
            trailing-icon="i-lucide-chevrons-up-down"
            aria-label="Account menu"
          />
        </UDropdownMenu>
      </template>
    </UDashboardSidebar>

    <slot />
    <div role="status" aria-live="polite" class="sr">{{ announce }}</div>
  </UDashboardGroup>
</template>
