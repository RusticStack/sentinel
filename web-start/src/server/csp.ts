// Inline blocks are allowed by their SHA-256 hash, computed per response from the HTML actually sent (no `unsafe-inline`
// for scripts or style elements). Pages are rendered whole before they are sent (the render handler, not the stream
// handler), so every inline script, including the router's dehydrated state, is known when the header is written.
const SCRIPT = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
const STYLE = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;

const cache = new Map<string, string>();
async function hash(text: string): Promise<string> {
  let value = cache.get(text);
  if (!value) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    value = `'sha256-${Buffer.from(digest).toString("base64")}'`;
    // Only small, repeated blocks are worth remembering; dehydrated data differs per response.
    if (text.length <= 4096) {
      if (cache.size >= 256) cache.clear();
      cache.set(text, value);
    }
  }
  return value;
}

export async function policyFor(html: string, extra: { formAction?: string[] } = {}): Promise<string> {
  const scripts = new Set<string>();
  for (const m of html.matchAll(SCRIPT)) if (!/\bsrc\s*=/i.test(m[1]!) && m[2]) scripts.add(await hash(m[2]));
  const styles = new Set<string>();
  for (const m of html.matchAll(STYLE)) if (m[1]) styles.add(await hash(m[1]));
  return [
    "default-src 'self'",
    `script-src 'self' ${[...scripts].join(" ")}`.trim(),
    `style-src 'self' ${[...styles].join(" ")}`.trim(),
    // Style attributes (bar widths, the log viewer's row offsets) cannot be hashed; only style-src-attr allows them.
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    `form-action 'self'${extra.formAction?.length ? " " + extra.formAction.join(" ") : ""}`,
    "frame-ancestors 'none'",
  ].join("; ");
}

export const SECURITY_HEADERS: Record<string, string> = {
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "permissions-policy": "accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), microphone=(), midi=(), payment=(), serial=(), usb=(), interest-cohort=()",
};
