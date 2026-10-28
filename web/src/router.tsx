import { createRouter } from "@tanstack/react-router";
import { routeTree } from "./routeTree.gen";

// Search parameters stay plain `key=value` pairs, as the Nuxt interface wrote them and GitHub check links and
// deep links carry them (`?pr=42`, `?step=1&seq=40`): the router's default would JSON-quote values that look like
// numbers. Every route validates what it reads (lib/search.ts).
function parseSearch(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of new URLSearchParams(text.startsWith("?") ? text.slice(1) : text)) if (!(k in out)) out[k] = v;
  return out;
}

function stringifySearch(search: Record<string, unknown>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(search)) {
    if (v === undefined || v === null || v === "") continue;
    q.set(k, String(v));
  }
  const text = q.toString();
  return text ? `?${text}` : "";
}

export function getRouter() {
  return createRouter({
    routeTree,
    scrollRestoration: true,
    defaultPreload: false,
    // Every view reads live controller state; a cached loader result is never shown as current.
    defaultStaleTime: 0,
    defaultPreloadStaleTime: 0,
    parseSearch,
    stringifySearch,
  });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof getRouter>;
  }
}
