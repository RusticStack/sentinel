import type { ApiErrorBody, Me, TenantChoice } from "~~/shared/types/api";

export class ApiError extends Error {
  status: number;
  code: string;
  details: Record<string, any>;
  constructor(status: number, body: ApiErrorBody | null) {
    super(body?.message || `HTTP ${status}`);
    this.status = status;
    this.code = body?.code || (status ? `http_${status}` : "network");
    this.details = body?.details || {};
  }
}

const CSRF_KEY = "sentinel-csrf";

export function csrfToken(): string | null {
  if (import.meta.server) return null;
  try { return localStorage.getItem(CSRF_KEY) || sessionStorage.getItem(CSRF_KEY); } catch { return null; }
}

export function setCsrfToken(value: string | null) {
  try {
    if (value) localStorage.setItem(CSRF_KEY, value); else localStorage.removeItem(CSRF_KEY);
    sessionStorage.removeItem(CSRF_KEY);
  } catch {}
}

export interface ApiOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export type EndReason = "expired" | "password-changed";

export function useEndSession() {
  // Captured at setup so the navigation can run after an await.
  const nuxtApp = useNuxtApp();
  const router = useRouter();
  const me = useState<Me | null>("me", () => null);
  const tenants = useState<TenantChoice[]>("tenants", () => []);
  return async function end(reason: EndReason) {
    if (reason === "expired" && !me.value) return;
    me.value = null;
    tenants.value = [];
    // After an expiry another tab may already hold a fresh CSRF token; keep it.
    if (reason !== "expired") setCsrfToken(null);
    const here = router.currentRoute.value;
    const query: Record<string, string> = { reason };
    if (reason === "expired" && here.path !== "/login" && here.fullPath !== "/") query.next = here.fullPath;
    await nuxtApp.runWithContext(() => navigateTo({ path: "/login", query }));
  };
}

export function useApi() {
  const fetcher = useRequestFetch();
  const end = import.meta.client ? useEndSession() : null;
  return async function api<T = any>(path: string, opts: ApiOptions = {}): Promise<T> {
    const method = opts.method || "GET";
    const headers: Record<string, string> = { accept: "application/json", ...opts.headers };
    const token = csrfToken();
    if (token && method !== "GET") headers["x-sentinel-csrf"] = token;
    try {
      return await fetcher<T>(path, {
        method,
        headers,
        body: opts.body === undefined ? undefined : (opts.body as any),
        signal: opts.signal,
        retry: 0,
      });
    } catch (e: any) {
      if (e?.name === "AbortError") throw e;
      const status = e?.response?.status ?? e?.statusCode ?? 0;
      if (status === 401 && end) void end("expired");
      throw new ApiError(status, (e?.data as ApiErrorBody) ?? null);
    }
  };
}
