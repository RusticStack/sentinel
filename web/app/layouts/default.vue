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
// The switcher keeps the three kinds of namespace apart: the person's own,
// organizations managed here, and organizations whose membership GitHub
// manages (marked, so nobody looks here to invite people to them).
const ROLE_NAMES: Record<string, string> = { reader: "Reader", operator: "Operator", admin: "Admin" };
const tenantItems = computed(() => {
  const personal: any[] = [];
  const app: any[] = [];
  const github: any[] = [];
  for (const t of session.tenants.value) {
    const role = ROLE_NAMES[t.role] ?? t.role;
    if (t.kind === "personal") personal.push({ label: t.slug, value: t.slug, description: `Personal · ${role}`, icon: "i-lucide-user" });
    else if (t.membership === "github") github.push({ label: t.slug, value: t.slug, description: `GitHub-managed · ${role}`, icon: "i-lucide-github" });
    else app.push({ label: t.slug, value: t.slug, description: role, icon: "i-lucide-building-2" });
  }
  const groups: any[][] = [];
  if (personal.length) groups.push([{ type: "label", label: "Personal" }, ...personal]);
  if (app.length) groups.push([{ type: "label", label: "Organizations" }, ...app]);
  if (github.length) groups.push([{ type: "label", label: "GitHub organizations" }, ...github]);
  return groups;
});
const activeIcon = computed(() => {
  const t = session.tenants.value.find((x) => x.slug === active.value);
  return t?.kind === "personal" ? "i-lucide-user" : t?.membership === "github" ? "i-lucide-github" : "i-lucide-building-2";
});

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
        { label: "Settings", icon: "i-lucide-settings", to: `/t/${slug}/settings` },
      ]
    : [];
  if (slug && (role.value === "admin" || session.me.value?.super_admin)) {
    main.push({ label: "Tenant admin", icon: "i-lucide-users", to: `/t/${slug}/admin` });
  }
  const platform: NavigationMenuItem[] = [{ label: "Organizations", icon: "i-lucide-building", to: "/organizations" }];
  if (session.me.value?.super_admin) platform.push({ label: "Platform", icon: "i-lucide-shield", to: "/platform" });
  return [main, platform];
});

function skipToMain() {
  document.getElementById("main")?.focus();
}

const account = computed<DropdownMenuItem[][]>(() => [
  [{ label: session.me.value?.username || shortId(session.me.value?.user), type: "label", icon: "i-lucide-user" }],
  [
    { label: "Account security", icon: "i-lucide-shield-check", to: "/account" },
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
          v-if="session.tenants.value.length && !collapsed"
          :model-value="active ?? undefined"
          :items="tenantItems"
          value-key="value"
          placeholder="Choose a namespace"
          :icon="activeIcon"
          aria-label="Active namespace"
          class="w-full"
          @update:model-value="(v: string) => switchTenant(v)"
        />
        <UNavigationMenu :collapsed="collapsed" :items="links[0]" orientation="vertical" tooltip aria-label="Tenant" />
        <UNavigationMenu :collapsed="collapsed" :items="links[1]" orientation="vertical" tooltip class="mt-auto" aria-label="Platform" />
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
