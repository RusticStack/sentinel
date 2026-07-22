import {
  applySecurityHeaders,
  clearSessionCookie,
  destroySession,
  readSessionCookie,
} from "../lib/auth.ts";
import { invalidateMembershipCache } from "../lib/github.ts";
import { define } from "../utils.ts";

/** Revoke server session + clear cookie; return to the locked login gate. */
export const handler = define.handlers({
  async GET(ctx) {
    if (ctx.state.user) {
      invalidateMembershipCache(ctx.state.user.login);
    }
    const sessionId = readSessionCookie(ctx.req, ctx.url);
    await destroySession(sessionId);
    const headers = new Headers({ Location: "/auth/login" });
    clearSessionCookie(headers, ctx.url);
    applySecurityHeaders(headers);
    return new Response(null, { status: 302, headers });
  },
});
