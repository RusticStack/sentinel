const CONTROL = /[\u0000-\u001f\u007f\\]/;
const BASE = "http://same-origin.invalid";

/// A post-sign-in destination that is an absolute path on this origin, or
/// `fallback`. Rejects protocol-relative (`//host`), backslash, control
/// character and any value the URL parser would resolve to another origin.
export function sameOriginPath(value: unknown, fallback = "/"): string {
  if (typeof value !== "string" || value.length > 2048) return fallback;
  if (!value.startsWith("/") || value.startsWith("//") || CONTROL.test(value)) return fallback;
  try {
    return new URL(value, BASE).origin === BASE ? value : fallback;
  } catch {
    return fallback;
  }
}
