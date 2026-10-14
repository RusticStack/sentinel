const CONTROL = /[\u0000-\u001f\u007f\\]/;
const BASE = "http://same-origin.invalid";

// Prevents open redirects: `//host` and backslash forms resolve to another origin.
export function sameOriginPath(value: unknown, fallback = "/"): string {
  if (typeof value !== "string" || value.length > 2048) return fallback;
  if (!value.startsWith("/") || value.startsWith("//") || CONTROL.test(value)) return fallback;
  try {
    return new URL(value, BASE).origin === BASE ? value : fallback;
  } catch {
    return fallback;
  }
}

// A cookie, not storage: the server-side render of `/` must be able to read it.
export const RETURN_COOKIE = "sentinel-return";
export const RETURN_SECONDS = 600;

export function pendingReturn(value: unknown): string | null {
  const dest = sameOriginPath(value);
  return new URL(dest, BASE).pathname === "/" ? null : dest;
}

export function returnCookie(path: string | null, secure: boolean): string {
  const value = path === null ? "" : encodeURIComponent(sameOriginPath(path));
  const age = path === null ? 0 : RETURN_SECONDS;
  return `${RETURN_COOKIE}=${value}; Path=/; Max-Age=${age}; SameSite=Lax${secure ? "; Secure" : ""}`;
}

export function rememberReturn(path: string | null) {
  try { document.cookie = returnCookie(path, location.protocol === "https:"); } catch { /* cookies off: the round trip ends on `/` */ }
}
