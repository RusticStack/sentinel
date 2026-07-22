/**
 * Dependency-free query/param allowlists.
 * Reject invalid values before they reach GitHub PAT calls.
 */

/** GitHub repository name max length. */
export const REPO_NAME_MAX_LENGTH = 100;

/**
 * Bare GitHub repo names: alphanumeric plus `.`, `_`, `-` (max 100 chars).
 */
const REPO_NAME_RE = /^[A-Za-z0-9._-]+$/;

/**
 * Allowlist a bare GitHub repository name from a query param.
 * Returns the trimmed name, or `null` if missing/empty/invalid.
 */
export function parseRepoName(raw: string | null | undefined): string | null {
  if (raw == null) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (trimmed.length > REPO_NAME_MAX_LENGTH) return null;
  if (!REPO_NAME_RE.test(trimmed)) return null;
  return trimmed;
}
