// The strangler front (plan 16.4, "Migration"): while SENTINEL_LEGACY_ORIGIN names the Nuxt process on loopback,
// every page path this application does not own yet is forwarded there, same origin and same cookie. A view
// moves by adding its pattern here once its browser checks pass; with no legacy origin, this application
// answers everything.
const OWNED: RegExp[] = [
  /^\/$/,
  /^\/_serverFn\//,
  /^\/_stream\//,
];

export function owned(path: string): boolean {
  return OWNED.some((re) => re.test(path));
}

export function legacyOrigin(): string | null {
  const origin = process.env.SENTINEL_LEGACY_ORIGIN;
  return origin ? origin.replace(/\/+$/, "") : null;
}
