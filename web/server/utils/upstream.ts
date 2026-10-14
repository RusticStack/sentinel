import type { H3Event } from "h3";

/// The controller's API base, from `NUXT_SENTINEL_API`.
export function sentinelApi(event: H3Event): string {
  return String(useRuntimeConfig(event).sentinelApi).replace(/\/+$/, "");
}

/// The caller's own credentials, forwarded as they came (the session
/// cookie, or a bearer), plus who is really calling: the controller counts
/// unauthenticated budgets per client by the last `X-Forwarded-For` entry
/// and trusts that header from its `trusted_proxies` only.
export function forwarded(event: H3Event): Record<string, string> {
  const out: Record<string, string> = { accept: "application/json" };
  const cookie = getRequestHeader(event, "cookie");
  const authorization = getRequestHeader(event, "authorization");
  if (cookie) out.cookie = cookie;
  if (authorization) out.authorization = authorization;
  const client = clientIp(event);
  if (client) out["x-forwarded-for"] = client;
  return out;
}

/// Who is really calling, as the controller should count them: the socket
/// peer, or, when `NUXT_CLIENT_IP_HEADER` names the header the reverse
/// proxy sets, that header's last entry. A client-sent `X-Forwarded-For` is
/// never passed on.
export function clientIp(event: H3Event): string {
  const name = String(useRuntimeConfig(event).clientIpHeader || "").toLowerCase();
  return clientAddress(getRequestIP(event), name ? getRequestHeader(event, name) : undefined);
}

/// Headers for a proxied request: the browser's own, minus anything that
/// names the client, plus the one address the controller counts.
export function upstreamHeaders(event: H3Event): Record<string, string> {
  const headers = getProxyRequestHeaders(event);
  for (const name of ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "x-real-ip"]) delete headers[name];
  const client = clientIp(event);
  if (client) headers["x-forwarded-for"] = client;
  return headers;
}

/// Wraps a request body so it fails once it passes `limit` bytes.
export function capBody(source: ReadableStream<Uint8Array>, limit: number, exceeded: { value: boolean }): ReadableStream<Uint8Array> {
  let seen = 0;
  return source.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.byteLength;
      if (seen > limit) { exceeded.value = true; throw new RangeError("body too large"); }
      controller.enqueue(chunk);
    },
  }));
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
