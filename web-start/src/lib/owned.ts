// The strangler front (plan 16.4, "Migration"): while SENTINEL_LEGACY_ORIGIN names the Nuxt process on loopback,
// every page path this application does not own yet is served by that process, same origin and same cookie; in the
// browser, a link to such a path is followed with a full page load. A view moves by adding its pattern here once its
// browser checks pass; with no legacy origin, this application answers everything.
const OWNED: RegExp[] = [
  /^\/$/,
  /^\/_serverFn\//,
  /^\/_stream\//,
];

export function owned(path: string): boolean {
  return OWNED.some((re) => re.test(path));
}

// Browser: whether the server said a legacy process is behind it (seeded by the root route).
let strangling = false;
export function setStrangling(on: boolean) { strangling = on; }
export function strangled(path: string): boolean { return strangling && !owned(path); }
