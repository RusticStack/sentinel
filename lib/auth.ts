/**
 * GitHub OAuth + server-side session helpers.
 *
 * Hardened against OWASP Session Management / OAuth2 cheat sheets + RFC 9700:
 * - Authorization code + confidential client + PKCE S256 + state
 * - Opaque httpOnly session cookie; authoritative record in Deno KV (no JWT session)
 * - No GitHub access token stored anywhere
 * - Handshake cookies: SameSite=Lax (required for IdP return); session: Strict
 * - __Host- / __Secure- cookie prefixes when HTTPS (ASVS V3.3)
 * - Timing-safe state compare; short absolute + idle session TTLs
 */
import { deleteCookie, getCookies, setCookie } from "@std/http/cookie";
import { timingSafeEqual } from "@std/crypto/timing-safe-equal";
import { jwtVerify, SignJWT } from "jose";
import {
  appBaseUrl,
  cookiesMustBeSecure,
  githubOAuthConfig,
  sessionSecret,
} from "./env.ts";
import {
  createSession,
  destroySession,
  type LoadedSession,
  loadSession,
  SESSION_ABSOLUTE_TTL_MS,
  touchSession,
} from "./sessions.ts";

export {
  createSession,
  destroySession,
  type LoadedSession,
  loadSession,
  touchSession,
};

/** Local HTTP cannot use __Host- (requires Secure); HTTPS uses ASVS prefixes. */
export function sessionCookieName(url: URL): string {
  return cookieSecure(url) ? "__Host-sentinel_session" : "sentinel_session";
}

export function oauthCookieName(url: URL): string {
  return cookieSecure(url) ? "__Secure-sentinel_oauth" : "sentinel_oauth";
}

const SESSION_TTL_SECONDS = Math.floor(SESSION_ABSOLUTE_TTL_MS / 1000);
const OAUTH_COOKIE_TTL_SECONDS = 60 * 10;
/** Login scope only; org runners/runs use GITHUB_PAT. */
const OAUTH_SCOPES = "read:org";
const JWT_ISS = "sentinel";

type OAuthHandshake = {
  state: string;
  verifier: string;
};

function sessionKey(): Uint8Array {
  return new TextEncoder().encode(sessionSecret());
}

function cookieSecure(url: URL): boolean {
  // Prefer APP_BASE_URL protocol so trustProxy / X-Forwarded-Proto cannot
  // accidentally clear the Secure flag on an HTTPS deployment.
  return cookiesMustBeSecure(url);
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll(
    "=",
    "",
  );
}

/** Constant-time string compare for OAuth state (CSRF). */
export function timingSafeEqualString(a: string, b: string): boolean {
  const ae = new TextEncoder().encode(a);
  const be = new TextEncoder().encode(b);
  if (ae.byteLength !== be.byteLength) {
    timingSafeEqual(ae, ae);
    return false;
  }
  return timingSafeEqual(ae, be);
}

/** Cryptographically random OAuth `state` (CSRF). */
export function createOAuthState(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

/** PKCE code_verifier + S256 code_challenge. */
export async function createPkcePair(): Promise<{
  verifier: string;
  challenge: string;
}> {
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return { verifier, challenge: base64Url(new Uint8Array(digest)) };
}

export function buildAuthorizeUrl(opts: {
  redirectUri: string;
  state: string;
  codeChallenge: string;
}): string {
  const { clientId } = githubOAuthConfig();
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: opts.redirectUri,
    scope: OAUTH_SCOPES,
    state: opts.state,
    code_challenge: opts.codeChallenge,
    code_challenge_method: "S256",
    allow_signup: "false",
  });
  return `https://github.com/login/oauth/authorize?${params}`;
}

export async function exchangeCodeForToken(opts: {
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<string> {
  const { clientId, clientSecret } = githubOAuthConfig();
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code: opts.code,
      redirect_uri: opts.redirectUri,
      code_verifier: opts.codeVerifier,
    }),
  });

  if (!res.ok) {
    throw new Error(`GitHub token exchange failed (${res.status})`);
  }

  const data = await res.json() as {
    access_token?: string;
    error?: string;
    error_description?: string;
  };

  if (!data.access_token) {
    throw new Error(
      data.error_description ?? data.error ?? "GitHub token exchange failed",
    );
  }
  return data.access_token;
}

/** Signed short-lived handshake cookie binding state + PKCE verifier. */
export async function sealOAuthHandshake(
  handshake: OAuthHandshake,
): Promise<string> {
  return await new SignJWT(handshake)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(JWT_ISS)
    .setAudience("sentinel-oauth")
    .setIssuedAt()
    .setExpirationTime(`${OAUTH_COOKIE_TTL_SECONDS}s`)
    .sign(sessionKey());
}

export async function openOAuthHandshake(
  token: string,
): Promise<OAuthHandshake | null> {
  try {
    const { payload } = await jwtVerify(token, sessionKey(), {
      algorithms: ["HS256"],
      issuer: JWT_ISS,
      audience: "sentinel-oauth",
    });
    const state = payload.state;
    const verifier = payload.verifier;
    if (typeof state !== "string" || typeof verifier !== "string") {
      return null;
    }
    return { state, verifier };
  } catch {
    return null;
  }
}

export function readSessionCookie(req: Request, url: URL): string | undefined {
  return getCookies(req.headers)[sessionCookieName(url)];
}

export function readOAuthHandshakeCookie(
  req: Request,
  url: URL,
): string | undefined {
  return getCookies(req.headers)[oauthCookieName(url)];
}

export function appendSessionCookie(
  headers: Headers,
  url: URL,
  sessionId: string,
): void {
  setCookie(headers, {
    name: sessionCookieName(url),
    value: sessionId,
    path: "/",
    httpOnly: true,
    secure: cookieSecure(url),
    sameSite: "Strict",
    maxAge: SESSION_TTL_SECONDS,
  });
}

export function appendOAuthHandshakeCookie(
  headers: Headers,
  url: URL,
  sealed: string,
): void {
  setCookie(headers, {
    name: oauthCookieName(url),
    value: sealed,
    path: "/auth",
    httpOnly: true,
    secure: cookieSecure(url),
    // Lax required: Strict is not sent on the cross-site return from GitHub.
    sameSite: "Lax",
    maxAge: OAUTH_COOKIE_TTL_SECONDS,
  });
}

export function clearOAuthCookies(headers: Headers, url: URL): void {
  deleteCookie(headers, oauthCookieName(url), {
    path: "/auth",
    secure: cookieSecure(url),
  });
  // Clear older split OAuth cookies if present.
  deleteCookie(headers, "sentinel_oauth_state", {
    path: "/auth",
    secure: cookieSecure(url),
  });
  deleteCookie(headers, "sentinel_oauth_verifier", {
    path: "/auth",
    secure: cookieSecure(url),
  });
}

export function clearSessionCookie(headers: Headers, url: URL): void {
  deleteCookie(headers, sessionCookieName(url), {
    path: "/",
    secure: cookieSecure(url),
  });
  // Clear non-prefixed name if we previously set it on HTTP and later moved to HTTPS.
  deleteCookie(headers, "sentinel_session", {
    path: "/",
    secure: cookieSecure(url),
  });
  deleteCookie(headers, "__Host-sentinel_session", {
    path: "/",
    secure: true,
  });
}

/**
 * Clear cookie + delete server record (OWASP: invalidate both sides).
 * Prefer this over clearSessionCookie alone when the opaque ID is known.
 */
export async function revokeSession(
  headers: Headers,
  url: URL,
  sessionId: string | undefined,
): Promise<void> {
  await destroySession(sessionId);
  clearSessionCookie(headers, url);
}

export function callbackRedirectUri(url: URL): string {
  return `${appBaseUrl(url)}/auth/callback`;
}

/** Security headers for auth-sensitive responses (OWASP). */
export function applySecurityHeaders(headers: Headers): void {
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set("Pragma", "no-cache");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-DNS-Prefetch-Control", "off");
}
