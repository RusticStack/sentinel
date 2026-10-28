// Server only: the controller's address and the header rules never reach the browser bundle.
import { clientAddress } from "./guard.ts";

// The old Nuxt names are accepted for one release (docs/compatibility.md).
const env = (name: string, legacy: string) => process.env[name] ?? process.env[legacy];

export function sentinelApi(): string {
  return String(env("SENTINEL_API", "NUXT_SENTINEL_API") || "http://127.0.0.1:7080").replace(/\/+$/, "");
}

function clientIpHeader(): string {
  // Empty trusts no header, so a client can never choose its own rate-limit bucket.
  return String(env("SENTINEL_CLIENT_IP_HEADER", "NUXT_CLIENT_IP_HEADER") || "").toLowerCase();
}

/** The socket peer as srvx (Nitro's Node server) reports it, with no proxy trusted. */
export function peerAddress(request: Request): string | undefined {
  const r = request as Request & { ip?: string; runtime?: { node?: { req?: { socket?: { remoteAddress?: string } } } } };
  const raw = r.runtime?.node?.req?.socket?.remoteAddress ?? r.ip;
  return raw?.startsWith("::ffff:") ? raw.slice(7) : raw;
}

export function clientIp(request: Request): string {
  const name = clientIpHeader();
  return clientAddress(peerAddress(request), name ? request.headers.get(name) ?? undefined : undefined);
}

// The controller counts unauthenticated budgets by the last X-Forwarded-For entry, trusted only from its trusted_proxies.
export function forwarded(request: Request): Record<string, string> {
  const out: Record<string, string> = { accept: "application/json" };
  const cookie = request.headers.get("cookie");
  const authorization = request.headers.get("authorization");
  if (cookie) out.cookie = cookie;
  if (authorization) out.authorization = authorization;
  const client = clientIp(request);
  if (client) out["x-forwarded-for"] = client;
  return out;
}

const HOP = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer", "host",
  "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "x-real-ip"];

/** The browser's request headers as they go to the controller: hop-by-hop and client-chosen forwarding headers dropped. */
export function upstreamHeaders(request: Request): Headers {
  const headers = new Headers(request.headers);
  for (const name of HOP) headers.delete(name);
  headers.delete("accept-encoding"); // the relay streams bodies as the controller sends them
  const client = clientIp(request);
  if (client) headers.set("x-forwarded-for", client);
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

export async function upstream(request: Request, path: string, signal: AbortSignal): Promise<{ status: number; body: any }> {
  const response = await fetch(sentinelApi() + path, { headers: forwarded(request), signal });
  const text = await response.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = null; }
  return { status: response.status, body };
}
