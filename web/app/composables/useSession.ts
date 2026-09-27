import type { Me, TenantChoice } from "~~/shared/types/api";

/// Who is signed in and the tenants they belong to. Loaded once per page
/// load (on the server for the first render), and re-read whenever the
/// controller refuses something: roles and memberships change under an
/// open session, and the interface follows the controller, not its memory.
export function useSession() {
  const me = useState<Me | null>("me", () => null);
  const tenants = useState<TenantChoice[]>("tenants", () => []);
  const loaded = useState<boolean>("session-loaded", () => false);
  const api = useApi();

  async function load(force = false) {
    if (loaded.value && !force) return me.value;
    try {
      me.value = await api<Me>("/api/v1/me");
      tenants.value = (await api<{ tenants: TenantChoice[] }>("/api/v1/tenants")).tenants;
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 401) throw e;
      me.value = null;
      tenants.value = [];
    }
    loaded.value = true;
    return me.value;
  }

  async function refreshTenants() {
    try {
      tenants.value = (await api<{ tenants: TenantChoice[] }>("/api/v1/tenants")).tenants;
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) await ended();
    }
  }

  async function ended() {
    me.value = null;
    tenants.value = [];
    const route = useRoute();
    await navigateTo({ path: "/login", query: route.path === "/login" ? {} : { next: route.fullPath } });
  }

  async function signOut() {
    try { await api("/api/v1/logout", { method: "POST", body: {} }); } catch { /* ended anyway */ }
    setCsrfToken(null);
    me.value = null;
    tenants.value = [];
    await navigateTo("/login");
  }

  const roleIn = (slug: string | undefined) => tenants.value.find((t) => t.slug === slug)?.role ?? null;

  return { me, tenants, load, refreshTenants, ended, signOut, roleIn };
}
