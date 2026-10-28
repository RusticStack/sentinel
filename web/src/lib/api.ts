// One API helper for both sides. In the server render it calls the controller directly with the browser's own
// cookie (api.server.ts, never in the browser bundle); in the browser it calls the same-origin proxied API and
// sends the session's CSRF secret on mutations. Either way the controller authorizes every call.
import { createIsomorphicFn } from "@tanstack/react-start";
import type { ApiErrorBody } from "./types";

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
  if (typeof window === "undefined") return null;
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

// The browser's handler for a 401 while someone is signed in (set by the root route).
let unauthorized: (() => void) | null = null;
export function onUnauthorized(fn: (() => void) | null) { unauthorized = fn; }

async function browserApi<T>(path: string, opts: ApiOptions): Promise<T> {
  const method = opts.method || "GET";
  const headers: Record<string, string> = { accept: "application/json", ...opts.headers };
  const token = csrfToken();
  if (token && method !== "GET") headers["x-sentinel-csrf"] = token;
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  let response: Response;
  try {
    response = await fetch(path, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body), signal: opts.signal, credentials: "same-origin" });
  } catch (e) {
    if ((e as Error)?.name === "AbortError") throw e;
    throw new ApiError(0, null);
  }
  const text = await response.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  if (!response.ok) {
    if (response.status === 401) unauthorized?.();
    throw new ApiError(response.status, body);
  }
  return body as T;
}

const call = createIsomorphicFn()
  .server(async (path: string, opts: ApiOptions): Promise<unknown> => {
    const { serverApi } = await import("./api.server.ts");
    return serverApi(path, opts);
  })
  .client((path: string, opts: ApiOptions): Promise<unknown> => browserApi(path, opts));

export function api<T = any>(path: string, opts: ApiOptions = {}): Promise<T> {
  return call(path, opts) as Promise<T>;
}

/** A cookie of the current request (server) or document (browser). */
export const readCookie = createIsomorphicFn()
  .server(async (name: string): Promise<string | null> => {
    const { requestCookie } = await import("./api.server.ts");
    return requestCookie(name);
  })
  .client(async (name: string): Promise<string | null> => {
    const m = new RegExp(`(?:^|; )${name}=([^;]*)`).exec(document.cookie);
    return m ? decodeURIComponent(m[1]!) : null;
  });
