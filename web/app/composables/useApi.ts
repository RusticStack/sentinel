import type { ApiErrorBody } from "~~/shared/types/api";

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

/// Call the controller's API: on the server with the browser's own cookie
/// (rendering a page as that person), in the browser through the same
/// origin. Mutations carry the session's CSRF secret.
export function useApi() {
  const fetcher = useRequestFetch();
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
      throw new ApiError(status, (e?.data as ApiErrorBody) ?? null);
    }
  };
}
