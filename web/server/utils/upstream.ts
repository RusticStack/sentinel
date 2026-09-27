import type { H3Event } from "h3";

/// The controller's API base, from `NUXT_SENTINEL_API`.
export function sentinelApi(event: H3Event): string {
  return String(useRuntimeConfig(event).sentinelApi).replace(/\/+$/, "");
}

/// The caller's own credentials, forwarded as they came (the session
/// cookie, or a bearer), plus who is really calling: the controller counts
/// unauthenticated budgets per client and trusts `X-Forwarded-For` from
/// loopback only.
export function forwarded(event: H3Event): Record<string, string> {
  const out: Record<string, string> = { accept: "application/json" };
  const cookie = getRequestHeader(event, "cookie");
  const authorization = getRequestHeader(event, "authorization");
  if (cookie) out.cookie = cookie;
  if (authorization) out.authorization = authorization;
  const peer = getRequestIP(event) || "";
  const prior = getRequestHeader(event, "x-forwarded-for");
  const chain = [prior, peer].filter(Boolean).join(", ");
  if (chain) out["x-forwarded-for"] = chain;
  return out;
}

/// Identifiers are checked before they go into an upstream URL.
export const RUN_ID = /^run_[0-9a-f-]{36}$/;
export const ATTEMPT_ID = /^att_[0-9a-f-]{36}$/;

export const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
  });

/// One upstream JSON call: status and body (`null` when not JSON).
export async function upstream(
  event: H3Event,
  path: string,
  signal: AbortSignal,
): Promise<{ status: number; body: any }> {
  const response = await fetch(sentinelApi(event) + path, { headers: forwarded(event), signal });
  const text = await response.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  return { status: response.status, body };
}
