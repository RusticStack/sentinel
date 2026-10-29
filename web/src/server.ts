// sentinel-web's server entry: the one origin in front of the controller (docs/web-ui.md). In order:
// the controller's own routes are relayed under the proxy allowlist and body ceilings; the live-update streams
// are served here; every other request is rendered by TanStack Start, whole, so its inline scripts can be hashed
// into the CSP header.
import { createServerEntry, createStartHandler, defaultRenderHandler } from "@tanstack/react-start/server";
import { bounceFor } from "./server/bounce.ts";
import { classifyProxyPath } from "./server/guard.ts";
import { proxy } from "./server/proxy.ts";
import { logStream, runStream } from "./server/streams.ts";
import { policyFor, SECURITY_HEADERS } from "./server/csp.ts";

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

// The GitHub App manifest form is posted to GitHub (docs/github-app.md): github.com, or the GitHub Enterprise Server
// (or test double) origin named by SENTINEL_GITHUB_WEB_URL, the same web URL the controller's GitHub configuration uses.
function githubOrigin(): string {
  try { return new URL(process.env.SENTINEL_GITHUB_WEB_URL || "https://github.com").origin; } catch { return "https://github.com"; }
}
const FORM_ACTIONS: Record<string, () => string[]> = {
  "/setup/github": () => [githubOrigin()],
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

    // GitHub's return to the two setup pages starts on another site, where the Strict session cookie is withheld.
    const bounced = bounceFor(request);
    if (bounced) return secure(bounced);

    const response = await start(request);
    if (!(response.headers.get("content-type") || "").startsWith("text/html")) return secure(response);
    const html = await response.text();
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    headers.set("content-security-policy", await policyFor(html, { formAction: FORM_ACTIONS[bare]?.() }));
    return secure(new Response(html, { status: response.status, statusText: response.statusText, headers }));
  },
});
