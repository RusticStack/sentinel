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

/// Where a round trip that leaves the interface (GitHub sign-in, linking
/// GitHub) continues. The controller ends it on `/` with a full page load,
/// so the marker is a cookie the server-side render of `/` can read; it
/// holds only a path on this origin, never a secret, and lives ten minutes.
export const RETURN_COOKIE = "sentinel-return";
export const RETURN_SECONDS = 600;

/// The page a pending return (the cookie's value) leads to, or `null` when
/// there is none or it would be `/` itself under any query or fragment
/// (following it would load the page that follows it again).
export function pendingReturn(value: unknown): string | null {
  const dest = sameOriginPath(value);
  return new URL(dest, BASE).pathname === "/" ? null : dest;
}

/// The `document.cookie` assignment that records `path` (made same-origin
/// first) as the pending return, or clears it when `path` is null.
export function returnCookie(path: string | null, secure: boolean): string {
  const value = path === null ? "" : encodeURIComponent(sameOriginPath(path));
  const age = path === null ? 0 : RETURN_SECONDS;
  return `${RETURN_COOKIE}=${value}; Path=/; Max-Age=${age}; SameSite=Lax${secure ? "; Secure" : ""}`;
}

/// Record the pending return in the browser, synchronously, so it is set
/// before an external navigation leaves the page.
export function rememberReturn(path: string | null) {
  try { document.cookie = returnCookie(path, location.protocol === "https:"); } catch { /* cookies off: the round trip ends on `/` */ }
}
