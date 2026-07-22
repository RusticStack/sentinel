/**
 * Shared Deno KV handle (SQLite file). Sessions and metric history share one DB;
 * keys stay namespaced (`sessions` vs `metrics`).
 */
import { optionalEnv } from "./env.ts";

const DEFAULT_DB_PATH = "data/sessions.db";

let kvPromise: Promise<Deno.Kv> | null = null;
let testOverride: Deno.Kv | null = null;

export function appKvPath(): string {
  return optionalEnv("SESSION_DB_PATH") ?? DEFAULT_DB_PATH;
}

/** Inject an in-memory KV for unit tests; pass null to clear. */
export function setAppKvForTests(kv: Deno.Kv | null): void {
  testOverride = kv;
  kvPromise = null;
}

export async function getAppKv(): Promise<Deno.Kv> {
  if (testOverride) return testOverride;
  if (!kvPromise) {
    const path = appKvPath();
    if (path !== ":memory:") {
      const parent = path.replace(/[\/\\][^\/\\]+$/, "");
      if (parent && parent !== path) {
        await Deno.mkdir(parent, { recursive: true });
      }
    }
    kvPromise = Deno.openKv(path);
  }
  return kvPromise;
}
