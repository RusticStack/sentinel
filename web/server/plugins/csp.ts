// A Content-Security-Policy for every page this process renders. Nuxt
// inlines a few scripts and styles whose text changes per build and per
// request (the runtime config, the colour-mode script, critical CSS), so
// each inline block is allowed by its SHA-256 instead of `unsafe-inline`.
// Only rendered pages get it: the controller's own pages, reached through
// the proxy, keep the policy the controller sets.
const SCRIPT = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
const STYLE = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;

const hashes = new Map<string, string>();
async function hash(text: string): Promise<string> {
  let value = hashes.get(text);
  if (!value) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    if (hashes.size >= 256) hashes.clear();
    value = `'sha256-${btoa(String.fromCharCode(...digest))}'`;
    hashes.set(text, value);
  }
  return value;
}

async function inline(parts: string[], pattern: RegExp, group: number, skip?: RegExp): Promise<Set<string>> {
  const out = new Set<string>();
  for (const part of parts) {
    for (const m of part.matchAll(pattern)) {
      if (skip && skip.test(m[1]!)) continue;
      if (m[group]) out.add(await hash(m[group]));
    }
  }
  return out;
}

export default defineNitroPlugin((nitro) => {
  if (import.meta.dev) return; // Vite's hot reload needs inline code and sockets
  nitro.hooks.hook("render:html", async (html, { event }) => {
    const parts = [...html.head, ...html.bodyPrepend, ...html.body, ...html.bodyAppend];
    const scripts = await inline(parts, SCRIPT, 2, /\bsrc\s*=/i);
    const styles = await inline(parts, STYLE, 1);
    // Style attributes (progress-bar widths) cannot be hashed, so they alone
    // may be inline; script and style elements stay hash-only.
    const policy = [
      "default-src 'self'",
      `script-src 'self' ${[...scripts].join(" ")}`.trim(),
      `style-src 'self' ${[...styles].join(" ")}`.trim(),
      "style-src-attr 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
    ].join("; ");
    setResponseHeader(event, "content-security-policy", policy);
  });
});
