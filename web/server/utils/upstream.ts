import type { H3Event } from "h3";

export function sentinelApi(event: H3Event): string {
  return String(useRuntimeConfig(event).sentinelApi).replace(/\/+$/, "");
}

// The controller counts unauthenticated budgets by the last X-Forwarded-For entry, trusted only from its trusted_proxies.
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

export function clientIp(event: H3Event): string {
  const name = String(useRuntimeConfig(event).clientIpHeader || "").toLowerCase();
  return clientAddress(getRequestIP(event), name ? getRequestHeader(event, name) : undefined);
}

export function upstreamHeaders(event: H3Event): Record<string, string> {
  const headers = getProxyRequestHeaders(event);
  for (const name of ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "x-real-ip"]) delete headers[name];
  const client = clientIp(event);
  if (client) headers["x-forwarded-for"] = client;
  return headers;
}

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

export const RUN_ID = /^run_[0-9a-f-]{36}$/;
export const ATTEMPT_ID = /^att_[0-9a-f-]{36}$/;

export const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
  });

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
