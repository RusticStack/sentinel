// sentinel-web's server entry: the one origin in front of the controller (docs/web-ui.md). In order:
// the controller's own routes are relayed under the proxy allowlist and body ceilings; the live-update streams
// are served here; unowned pages go to the legacy process while the strangler migration lasts; every other
// request is rendered by TanStack Start, whole, so its inline scripts can be hashed into the CSP header.
import { createServerEntry, createStartHandler, defaultRenderHandler } from "@tanstack/react-start/server";
import { classifyProxyPath } from "./server/guard.ts";
import { proxy } from "./server/proxy.ts";
import { logStream, runStream } from "./server/streams.ts";
import { legacyOrigin, owned } from "./server/owned.ts";
import { policyFor, SECURITY_HEADERS } from "./server/csp.ts";
import { clientIp } from "./server/upstream.ts";

const start = createStartHandler(defaultRenderHandler);

function rawPath(request: Request): string {
  // The path exactly as the client sent it: the request's URL has been through the URL parser, which decodes `%2e` and
  // resolves dot segments the allowlist must see, so Node's own request target is read when there is one.
  const target = (request as Request & { runtime?: { node?: { req?: { url?: string } } } }).runtime?.node?.req?.url;
  if (typeof target === "string" && target.startsWith("/")) return target;
  const url = request.url;
  const at = url.indexOf("/", url.indexOf("//") + 2);
  return at < 0 ? "/" : url.slice(at);
}

function secure(response: Response): Response {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) if (!response.headers.has(name)) response.headers.set(name, value);
  return response;
}

async function toLegacy(request: Request, origin: string, path: string): Promise<Response> {
  const headers = new Headers(request.headers);
  for (const name of ["x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "forwarded", "x-real-ip", "host", "connection", "accept-encoding"]) headers.delete(name);
  const client = clientIp(request);
  if (client) headers.set("x-forwarded-for", client);
  const init: RequestInit & { duplex?: "half" } = { method: request.method, headers, redirect: "manual" };
  if (request.body && request.method !== "GET" && request.method !== "HEAD") { init.body = request.body; init.duplex = "half"; }
  const answer = await fetch(origin + path, init);
  const out = new Headers(answer.headers);
  if (answer.headers.has("content-encoding")) { out.delete("content-encoding"); out.delete("content-length"); }
  out.delete("transfer-encoding");
  return new Response(answer.body, { status: answer.status, headers: out });
}

const FORM_ACTIONS: Record<string, string[]> = {
  // The GitHub App manifest form is posted to GitHub (docs/github-app.md).
  "/setup/github": ["https://github.com"],
};

export default createServerEntry({
  async fetch(request) {
    const path = rawPath(request);
    const verdict = classifyProxyPath(path, request.method);
    if (verdict.kind === "reject") return secure(new Response("Bad Request", { status: 400 }));
    if (verdict.kind === "proxy") return proxy(request, path, verdict);

    const bare = path.split("?", 1)[0]!;
    if (request.method === "GET" && bare.startsWith("/_stream/run/")) return secure(runStream(request, bare.slice(13)));
    if (request.method === "GET" && bare.startsWith("/_stream/log/")) return secure(logStream(request, bare.slice(13), new URL(request.url).searchParams));

    const legacy = legacyOrigin();
    if (legacy && !owned(bare)) {
      try { return await toLegacy(request, legacy, path); } catch { return secure(new Response("Bad Gateway", { status: 502 })); }
    }

    const response = await start(request);
    if (!(response.headers.get("content-type") || "").startsWith("text/html")) return secure(response);
    const html = await response.text();
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    headers.set("content-security-policy", await policyFor(html, { formAction: FORM_ACTIONS[bare] }));
    return secure(new Response(html, { status: response.status, statusText: response.statusText, headers }));
  },
});
