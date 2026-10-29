// GitHub sends the person back to /setup/github/created and /setup/github/installed with a navigation that starts on
// github.com. The session cookie is SameSite=Strict (the controller's cookie, docs/web-ui.md), so such a navigation
// arrives without it, and the server render would send the person to the sign-in page, where a fresh sign-in cannot
// spend a state bound to the session that started the setup. These two pages are therefore answered, when the
// navigation is cross-site, with a page that only sends the browser on to the same address: that second request is
// started by this origin's own document, so the cookie is sent and the page renders as the signed-in person.
//
// Only the values the pages read are carried on, each checked against the shape the page itself requires and
// re-encoded, so nothing else in the incoming address survives and nothing is reflected unescaped.
import { CODE, INSTALLATION, SETUP_ACTION, STATE } from "../lib/githubApp.ts";

const RETURNS: Record<string, ReadonlyArray<readonly [string, RegExp]>> = {
  "/setup/github/created": [["code", CODE], ["state", STATE]],
  "/setup/github/installed": [["installation_id", INSTALLATION], ["setup_action", SETUP_ACTION], ["state", STATE]],
};

function attribute(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** The same-origin refresh page for a cross-site navigation to one of the two return pages, otherwise null. */
export function bounceFor(request: Request): Response | null {
  if (request.method !== "GET") return null;
  const headers = request.headers;
  // A browser says where a navigation started; one that says nothing (or says it is this site's) is never bounced,
  // so the refresh below, which is same-origin, cannot loop.
  if (headers.get("sec-fetch-site") !== "cross-site" || headers.get("sec-fetch-dest") !== "document") return null;
  let url: URL;
  try { url = new URL(request.url); } catch { return null; }
  const wanted = RETURNS[url.pathname];
  if (!wanted) return null;
  const kept = new URLSearchParams();
  for (const [name, shape] of wanted) {
    const value = url.searchParams.get(name);
    if (value !== null && shape.test(value)) kept.append(name, value);
  }
  const query = kept.toString();
  const target = url.pathname + (query ? `?${query}` : "");
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">`
    + `<meta http-equiv="refresh" content="0;url=${attribute(target)}"><title>Sentinel</title></head><body><p>Continuing…</p></body></html>`;
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    },
  });
}
