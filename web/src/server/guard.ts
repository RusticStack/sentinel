const V4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
function isAddress(s: string): boolean {
  if (V4.test(s)) return true;
  if (!s.includes(":") || !/^[0-9a-f:.]+$/i.test(s)) return false;
  try { new URL(`http://[${s}]/`); return true; } catch { return false; }
}

const PREFIXES = ["/api/v1/", "/oauth/", "/auth/github/", "/.well-known/"];
const EXACT = new Set(["/device", "/mcp", "/api/v1"]);

export const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Must match the controller's intake limits (MAX_API_BODY_BYTES and siblings); change them together.
const API_BODY = 1 << 20;
const UPLOAD_CHUNK = 8 << 20;
const WEBHOOK_BODY = 4 << 20;
const MCP_BODY = 2 << 20;

const isProxied = (bare: string) => EXACT.has(bare) || PREFIXES.some((p) => bare.startsWith(p));

// Paths that could mean one thing here and another upstream: refused, never forwarded.
const AMBIGUOUS = /[\\\u0000-\u001f\u007f]|%(?:2e|2f|5c|00|25)/i;

function dotSegments(bare: string): boolean {
  const segments = bare.split("/");
  for (let i = 1; i < segments.length; i++) {
    const s = segments[i]!;
    if (s === "." || s === ".." || (s === "" && i < segments.length - 1)) return true;
  }
  return false;
}

function resolved(bare: string): string {
  let decoded = bare;
  try { decoded = decodeURIComponent(bare); } catch { /* keep raw */ }
  const out: string[] = [];
  for (const s of decoded.replaceAll("\\", "/").split("/").slice(1)) {
    if (s === "" || s === ".") continue;
    if (s === "..") out.pop();
    else out.push(s);
  }
  return "/" + out.join("/");
}

export type ProxyVerdict =
  | { kind: "pass" }
  | { kind: "reject" }
  | { kind: "proxy"; limit: number };

export function classifyProxyPath(raw: string, method: string): ProxyVerdict {
  if (!raw.startsWith("/")) return { kind: "pass" };
  const cut = raw.indexOf("?");
  const bare = cut < 0 ? raw : raw.slice(0, cut);
  const ambiguous = AMBIGUOUS.test(bare) || dotSegments(bare);
  if (isProxied(bare)) {
    return ambiguous ? { kind: "reject" } : { kind: "proxy", limit: bodyLimit(bare, method) };
  }
  if (ambiguous && isProxied(resolved(bare))) return { kind: "reject" };
  return { kind: "pass" };
}

function bodyLimit(bare: string, method: string): number {
  if (method === "PUT" && bare.startsWith("/api/v1/uploads/")) return UPLOAD_CHUNK;
  if (bare.startsWith("/api/v1/hooks/")) return WEBHOOK_BODY;
  if (bare === "/mcp") return MCP_BODY;
  return API_BODY;
}

// Loopback, private, link-local and unique-local addresses: a reverse proxy's hop, never a remote browser.
function isInternal(address: string): boolean {
  if (V4.test(address)) {
    const [a, b] = address.split(".").map(Number) as [number, number];
    return a === 127 || a === 10 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  const lower = address.toLowerCase();
  return lower === "::1" || lower === "::" || /^f[cd][0-9a-f]{2}:/.test(lower) || /^fe[89ab][0-9a-f]:/.test(lower);
}

/**
 * The client the controller should rate-limit: the last entry of the configured header when it is an address, else the
 * socket peer when it is a remote one. An internal peer is a reverse proxy, and naming it would give every client behind
 * it one shared allowance; naming nobody lets the controller key on the connection instead.
 */
export function clientAddress(peer: string | undefined, headerValue: string | undefined): string {
  if (headerValue) {
    const last = headerValue.slice(headerValue.lastIndexOf(",") + 1).trim();
    const bare = last.startsWith("[") && last.endsWith("]") ? last.slice(1, -1) : last;
    if (isAddress(bare)) return bare;
  }
  return peer && isAddress(peer) && !isInternal(peer) ? peer : "";
}
