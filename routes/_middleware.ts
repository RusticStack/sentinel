import {
  applySecurityHeaders,
  clearSessionCookie,
  destroySession,
  loadSession,
  readSessionCookie,
  touchSession,
} from "../lib/auth.ts";
import { checkOrgMembership } from "../lib/github.ts";
import { define } from "../utils.ts";

function isAuthPath(pathname: string): boolean {
  return pathname === "/auth" || pathname.startsWith("/auth/");
}

function isApiPath(pathname: string): boolean {
  return pathname === "/api" || pathname.startsWith("/api/");
}

function withSecurity(res: Response): Response {
  applySecurityHeaders(res.headers);
  return res;
}

function jsonError(
  status: number,
  error: string,
  extraHeaders?: Headers,
): Response {
  const headers = new Headers(extraHeaders);
  headers.set("Content-Type", "application/json; charset=utf-8");
  applySecurityHeaders(headers);
  return Response.json({ error }, { status, headers });
}

/**
 * Auth gate for all FS routes (OWASP session + org gate).
 * - Load opaque session from Deno KV; re-check org membership via GITHUB_PAT (5 min cache).
 * - Skip *redirect* for `/auth/*` so login/callback/denied stay reachable.
 * - `/api/*` returns JSON 401/403/503 instead of HTML redirects (curl / islands friendly).
 * - Confirmed non-member → revoke server session + `/auth/denied` (pages) or 403 JSON (API).
 * - Upstream membership errors → 503 without clearing the session (fail closed, no fixation wipe).
 */
export default define.middleware(async (ctx) => {
  const sessionId = readSessionCookie(ctx.req, ctx.url);
  const authRoute = isAuthPath(ctx.url.pathname);
  const apiRoute = isApiPath(ctx.url.pathname);

  if (!sessionId) {
    if (authRoute) return withSecurity(await ctx.next());
    if (apiRoute) return jsonError(401, "Unauthorized");
    const headers = new Headers({ Location: "/auth/login" });
    applySecurityHeaders(headers);
    return new Response(null, { status: 302, headers });
  }

  const session = await loadSession(sessionId);
  if (!session) {
    const headers = new Headers();
    clearSessionCookie(headers, ctx.url);
    applySecurityHeaders(headers);
    if (authRoute) {
      const res = await ctx.next();
      headers.forEach((v, k) => res.headers.append(k, v));
      return res;
    }
    if (apiRoute) {
      headers.set("Content-Type", "application/json; charset=utf-8");
      return Response.json({ error: "Unauthorized" }, { status: 401, headers });
    }
    headers.set("Location", "/auth/login");
    return new Response(null, { status: 302, headers });
  }

  const membership = await checkOrgMembership(session.user.login);

  if (membership === "error") {
    if (authRoute) return withSecurity(await ctx.next());
    if (apiRoute) {
      return jsonError(503, "Authentication service temporarily unavailable");
    }
    const headers = new Headers({
      "Content-Type": "text/plain; charset=utf-8",
    });
    applySecurityHeaders(headers);
    return new Response(
      "Authentication service temporarily unavailable. Try again shortly.",
      { status: 503, headers },
    );
  }

  if (membership === "inactive") {
    const headers = new Headers();
    await destroySession(sessionId);
    clearSessionCookie(headers, ctx.url);
    applySecurityHeaders(headers);
    if (authRoute) {
      const res = await ctx.next();
      headers.forEach((v, k) => res.headers.append(k, v));
      return res;
    }
    if (apiRoute) {
      headers.set("Content-Type", "application/json; charset=utf-8");
      return Response.json({ error: "Forbidden" }, { status: 403, headers });
    }
    headers.set("Location", "/auth/denied");
    return new Response(null, { status: 302, headers });
  }

  // Sliding idle window: absolute TTL still enforced in the store.
  await touchSession(sessionId);
  ctx.state.user = session.user;
  return withSecurity(await ctx.next());
});
