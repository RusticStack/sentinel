export { owned } from "../lib/owned.ts";

export function legacyOrigin(): string | null {
  const origin = process.env.SENTINEL_LEGACY_ORIGIN;
  return origin ? origin.replace(/\/+$/, "") : null;
}
