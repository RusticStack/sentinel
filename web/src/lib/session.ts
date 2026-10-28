// The signed-in person and their namespaces. The server render reads them per request; the browser keeps one
// copy (seeded from the render) and re-reads the tenant list on refusals, because roles and memberships change
// under an open session.
import { useSyncExternalStore } from "react";
import { useLoaderData } from "@tanstack/react-router";
import type { Me, TenantChoice } from "./types";
import { api, ApiError, setCsrfToken } from "./api.ts";

export interface SessionState { me: Me | null; tenants: TenantChoice[] }
export type EndReason = "expired" | "password-changed";

const EMPTY: SessionState = { me: null, tenants: [] };
let state: SessionState | null = null; // browser only
const listeners = new Set<() => void>();
const set = (next: SessionState) => { state = next; for (const l of listeners) l(); };

export async function fetchSession(): Promise<SessionState> {
  try {
    const me = await api<Me>("/api/v1/me");
    const tenants = (await api<{ tenants: TenantChoice[] }>("/api/v1/tenants")).tenants;
    return { me, tenants };
  } catch (e) {
    if (!(e instanceof ApiError) || e.status !== 401) throw e;
    return EMPTY;
  }
}

/** The session for a route guard: per request on the server, the kept copy in the browser. */
export async function loadSession(force = false): Promise<SessionState> {
  if (typeof window === "undefined") return fetchSession();
  if (state && !force) return state;
  set(await fetchSession());
  return state!;
}

export function seedSession(initial: SessionState) {
  if (typeof window !== "undefined" && state === null) state = initial;
}

export async function refreshTenants() {
  try {
    const tenants = (await api<{ tenants: TenantChoice[] }>("/api/v1/tenants")).tenants;
    set({ me: state?.me ?? null, tenants });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) await ended();
  }
}

export function setSession(next: SessionState) { set(next); }
export function markSteppedUp() { if (state?.me) set({ ...state, me: { ...state.me, stepped_up: true } }); }

// Navigation is handed in by the root route (the router lives there).
let go: ((to: string, replace?: boolean) => Promise<void> | void) | null = null;
export function setNavigator(fn: typeof go) { go = fn; }

/** The session ended under an open page: forget the person once, however many requests were refused together. */
export async function ended(reason: EndReason = "expired") {
  if (reason === "expired" && !state?.me) return;
  set(EMPTY);
  // After an expiry another tab may already hold a fresh CSRF secret; keep it.
  if (reason !== "expired") setCsrfToken(null);
  const here = location.pathname + location.search;
  const query = new URLSearchParams({ reason });
  if (reason === "expired" && location.pathname !== "/login" && here !== "/") query.set("next", here);
  await go?.(`/login?${query}`);
}

export async function signOut(next?: string) {
  set(EMPTY); // a refused logout is not a session that "expired"
  try { await api("/api/v1/logout", { method: "POST", body: {} }); } catch { /* gone already */ }
  setCsrfToken(null);
  await go?.(next ? `/login?next=${encodeURIComponent(next)}` : "/login");
}

const subscribe = (l: () => void) => { listeners.add(l); return () => listeners.delete(l); };

export function useSession() {
  const initial = useLoaderData({ from: "__root__" }).session as SessionState;
  const s = useSyncExternalStore(subscribe, () => state ?? initial, () => initial);
  const roleIn = (slug: string | null | undefined) => s.tenants.find((t) => t.slug === slug)?.role ?? null;
  return { me: s.me, tenants: s.tenants, roleIn };
}
