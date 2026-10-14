// Pure request guards for the proxy: which paths belong to the controller,
// how large a body each may carry, and which address a request is counted
// under. No framework imports, so they are testable on their own.

// An IPv4 or IPv6 literal (no zone, no port), without node:net.
const V4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
function isAddress(s: string): boolean {
  if (V4.test(s)) return true;
  if (!s.includes(":") || !/^[0-9a-f:.]+$/i.test(s)) return false;
  try { new URL(`http://[${s}]/`); return true; } catch { return false; }
}

// Everything the controller serves itself — the API, the OAuth
// authorization server and its consent/device pages, GitHub sign-in, the
// discovery documents and remote MCP.
const PREFIXES = ["/api/v1/", "/oauth/", "/auth/github/", "/.well-known/"];
const EXACT = new Set(["/device", "/mcp", "/api/v1"]);

/// The methods whose body is forwarded.
export const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// Body ceilings that match what the controller itself accepts, so an
// oversized body is refused here before it is relayed (protocol limits:
// MAX_API_BODY_BYTES, MAX_UPLOAD_CHUNK, MAX_WEBHOOK_BODY_BYTES in intake,
// MAX_MESSAGE_BYTES). Change them together with the controller.
const API_BODY = 1 << 20;
const UPLOAD_CHUNK = 8 << 20;
const WEBHOOK_BODY = 4 << 20;
const MCP_BODY = 2 << 20;

const isProxied = (bare: string) => EXACT.has(bare) || PREFIXES.some((p) => bare.startsWith(p));

// Anything that lets a path mean one thing here and another upstream:
// backslashes, encoded dots/slashes/backslashes/NUL/percent, control
// characters, and dot or empty segments.
const AMBIGUOUS = /[\\\u0000-\u001f\u007f]|%(?:2e|2f|5c|00|25)/i;

function dotSegments(bare: string): boolean {
  const segments = bare.split("/");
  for (let i = 1; i < segments.length; i++) {
    const s = segments[i]!;
    if (s === "." || s === ".." || (s === "" && i < segments.length - 1)) return true;
  }
  return false;
}

/// The path the URL parser upstream would end up with, for deciding whether
/// an ambiguous path was aimed at the controller.
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

/// Decides, from the raw request target, whether the controller serves it.
/// The allowlist is checked on the path exactly as it will be sent (the query
/// string is never inspected: percent-encoding is normal there), and a
/// target that is ambiguous is refused when it could reach the controller
/// under any reading, never forwarded.
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

/// The address a request is counted under, forwarded to the controller as
/// the only `X-Forwarded-For` entry. With no header configured (`headerValue`
/// undefined) it is the socket peer. With one configured (the header the
/// operator's reverse proxy sets), it is that header's last entry — the one
/// the proxy itself appended; a client's own earlier entries are never used
/// — when it is a valid address, else the peer. A client therefore cannot
/// pick its bucket.
export function clientAddress(peer: string | undefined, headerValue: string | undefined): string {
  if (headerValue) {
    const last = headerValue.slice(headerValue.lastIndexOf(",") + 1).trim();
    const bare = last.startsWith("[") && last.endsWith("]") ? last.slice(1, -1) : last;
    if (isAddress(bare)) return bare;
  }
  return peer && isAddress(peer) ? peer : "";
}
