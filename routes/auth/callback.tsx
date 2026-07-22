import {
  appendSessionCookie,
  applySecurityHeaders,
  callbackRedirectUri,
  clearOAuthCookies,
  clearSessionCookie,
  createSession,
  destroySession,
  exchangeCodeForToken,
  openOAuthHandshake,
  readOAuthHandshakeCookie,
  readSessionCookie,
  timingSafeEqualString,
} from "../../lib/auth.ts";
import {
  getAuthenticatedUser,
  invalidateMembershipCache,
  isActiveOrgMember,
} from "../../lib/github.ts";
import { define } from "../../utils.ts";

/**
 * GitHub OAuth callback: exchange code, verify active org membership, set session.
 * User OAuth token is used only here for GET /user, then discarded (never stored).
 * Non-members get no session cookie and are sent to `/auth/denied`.
 */
export const handler = define.handlers({
  async GET(ctx) {
    const url = ctx.url;
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const oauthError = url.searchParams.get("error");

    const headers = new Headers();
    clearOAuthCookies(headers, url);
    // Session fixation: revoke any prior server session and clear cookie.
    const priorId = readSessionCookie(ctx.req, url);
    await destroySession(priorId);
    clearSessionCookie(headers, url);
    applySecurityHeaders(headers);

    if (oauthError) {
      headers.set("Location", "/auth/login?error=denied");
      return new Response(null, { status: 302, headers });
    }

    const sealed = readOAuthHandshakeCookie(ctx.req, url);
    const handshake = sealed ? await openOAuthHandshake(sealed) : null;
    if (
      !code || !state || !handshake ||
      !timingSafeEqualString(state, handshake.state)
    ) {
      headers.set("Location", "/auth/login?error=state");
      return new Response(null, { status: 302, headers });
    }

    try {
      const redirectUri = callbackRedirectUri(url);
      const accessToken = await exchangeCodeForToken({
        code,
        redirectUri,
        codeVerifier: handshake.verifier,
      });
      const user = await getAuthenticatedUser(accessToken);
      // Drop the user access token from memory after identity fetch.
      // Membership is confirmed with GITHUB_PAT (not the user token).
      invalidateMembershipCache(user.login);
      const member = await isActiveOrgMember(user.login);

      if (!member) {
        headers.set("Location", "/auth/denied");
        return new Response(null, { status: 302, headers });
      }

      const sessionId = await createSession(user);
      appendSessionCookie(headers, url, sessionId);
      headers.set("Location", "/");
      return new Response(null, { status: 302, headers });
    } catch (err) {
      console.error(
        "OAuth callback failed:",
        err instanceof Error ? err.message : "unknown error",
      );
      headers.set("Location", "/auth/login?error=oauth");
      return new Response(null, { status: 302, headers });
    }
  },
});
