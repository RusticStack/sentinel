// Everything the controller serves itself — the API, the OAuth
// authorization server and its consent/device pages, GitHub sign-in, the
// discovery documents and remote MCP — passes through to it unchanged,
// cookies and redirects included, so the browser sees one origin.
const PREFIXES = ["/api/v1/", "/oauth/", "/auth/github/", "/.well-known/"];
const EXACT = new Set(["/device", "/mcp", "/api/v1"]);

export default defineEventHandler((event) => {
  const path = event.path;
  const bare = path.split("?", 1)[0]!;
  if (!EXACT.has(bare) && !PREFIXES.some((p) => bare.startsWith(p))) return;
  const headers: Record<string, string> = {};
  const peer = getRequestIP(event) || "";
  const prior = getRequestHeader(event, "x-forwarded-for");
  const chain = [prior, peer].filter(Boolean).join(", ");
  if (chain) headers["x-forwarded-for"] = chain;
  return proxyRequest(event, sentinelApi(event) + path, {
    headers,
    fetchOptions: { redirect: "manual" },
  });
});
