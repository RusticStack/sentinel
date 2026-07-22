/**
 * Env helpers for Sentinel.
 * Prefer loading `.env` locally; production uses systemd EnvironmentFile.
 */
import { loadSync } from "@std/dotenv";

try {
  loadSync({ export: true });
} catch {
  // Missing .env is fine when vars come from the process environment.
}

const MIN_SESSION_SECRET_LEN = 32;

export function requireEnv(name: string): string {
  const value = Deno.env.get(name)?.trim();
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export function optionalEnv(name: string): string | undefined {
  const value = Deno.env.get(name)?.trim();
  return value || undefined;
}

export function githubOrg(): string {
  return requireEnv("GH_ORG");
}

export function githubOAuthConfig() {
  return {
    clientId: requireEnv("GITHUB_CLIENT_ID"),
    clientSecret: requireEnv("GITHUB_CLIENT_SECRET"),
  };
}

/** Classic PAT for org membership re-checks and org-scoped GitHub APIs. */
export function githubPat(): string {
  return requireEnv("GITHUB_PAT");
}

/** Expected self-hosted runner instance count (dashboard hint). Default 4. */
export function runnerCount(): number {
  const raw = optionalEnv("RUNNER_COUNT");
  if (!raw) return 4;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 4;
}

/**
 * Session HMAC key (OAuth handshake seal + session-id hashing).
 * OWASP: high-entropy secret, never commit. Require ≥32 characters.
 */
export function sessionSecret(): string {
  const value = requireEnv("SESSION_SECRET");
  if (value.length < MIN_SESSION_SECRET_LEN) {
    throw new Error(
      `SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LEN} characters`,
    );
  }
  return value;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" ||
    hostname === "[::1]" || hostname === "::1";
}

/**
 * Canonical public origin for OAuth redirect_uri and Secure-cookie decisions.
 * OWASP/RFC 9700: do not trust Host / X-Forwarded-* alone in production.
 * - Required whenever the request host is not loopback
 * - Optional on localhost / 127.0.0.1 for local HTTP dev
 */
export function appBaseUrl(requestUrl: URL): string {
  const configured = optionalEnv("APP_BASE_URL");
  if (configured) {
    let u: URL;
    try {
      u = new URL(configured);
    } catch {
      throw new Error(
        "APP_BASE_URL must be an absolute URL, e.g. https://sentinel.example.com",
      );
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      throw new Error("APP_BASE_URL must be http(s)");
    }
    return u.origin;
  }

  if (isLoopbackHost(requestUrl.hostname)) {
    return requestUrl.origin;
  }

  throw new Error(
    "APP_BASE_URL is required for non-localhost deployments (e.g. https://sentinel.example.com)",
  );
}

/** True when cookies must be Secure: prefer configured HTTPS APP_BASE_URL. */
export function cookiesMustBeSecure(requestUrl: URL): boolean {
  const configured = optionalEnv("APP_BASE_URL");
  if (configured) {
    return new URL(configured).protocol === "https:";
  }
  return requestUrl.protocol === "https:";
}
