import type { ApiErrorBody, Me, TenantChoice } from "~~/shared/types/api";

/// A refusal from the controller, with its `sentinel.error/1` code.
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
  } catch { /* storage off */ }
}

export interface ApiOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

/// Why sign-in is asked for again; the sign-in page says it in words.
export type EndReason = "expired" | "password-changed";

/// Forget the signed-in person and go to sign-in, coming back to the page
/// that was open (validated there by `sameOriginPath`). Bound to the Nuxt
/// app at setup, so it may run after any `await`. A call while nobody is
/// signed in does nothing: several requests refused together, or a refused
/// request and a refused stream, lead to one navigation.
export function useEndSession() {
  const nuxtApp = useNuxtApp();
  const router = useRouter();
  const me = useState<Me | null>("me", () => null);
  const tenants = useState<TenantChoice[]>("tenants", () => []);
  return async function end(reason: EndReason) {
    if (!me.value) return;
    me.value = null;
    tenants.value = [];
    // The secret is shared by every tab: after an expiry another tab may
    // already have signed in again and stored a new one. The next sign-in
    // replaces a stale one anyway.
    if (reason !== "expired") setCsrfToken(null);
    const here = router.currentRoute.value;
    const query: Record<string, string> = { reason };
    if (reason === "expired" && here.path !== "/login" && here.fullPath !== "/") query.next = here.fullPath;
    await nuxtApp.runWithContext(() => navigateTo({ path: "/login", query }));
  };
}

/// Call the controller's API: on the server with the browser's own cookie
/// (rendering a page as that person), in the browser through the same
/// origin. Mutations carry the session's CSRF secret. In the browser, a
/// `401` while someone was signed in means the session ended under the
/// open page (its deadline passed, it was revoked, the password changed
/// elsewhere): the page goes to sign-in and says so, and the caller still
/// gets the error.
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
