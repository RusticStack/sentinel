import type { Me, TenantChoice } from "~~/shared/types/api";
import type { EndReason } from "./useApi";

// Tenants are re-read on refusal: roles and memberships change under an open session.
export function useSession() {
  const me = useState<Me | null>("me", () => null);
  const tenants = useState<TenantChoice[]>("tenants", () => []);
  const loaded = useState<boolean>("session-loaded", () => false);
  const api = useApi();
  const end = useEndSession();

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

  const ended = (reason: EndReason = "expired") => end(reason);

  async function signOut(next?: string) {
    me.value = null; // a refused logout is not a session that "expired"
    try { await api("/api/v1/logout", { method: "POST", body: {} }); } catch {}
    setCsrfToken(null);
    tenants.value = [];
    await navigateTo({ path: "/login", query: next ? { next } : {} });
  }

  const roleIn = (slug: string | undefined) => tenants.value.find((t) => t.slug === slug)?.role ?? null;

  return { me, tenants, load, refreshTenants, ended, signOut, roleIn };
}
