import { useEffect, useState, type ReactNode } from "react";
import { createRootRoute, HeadContent, Outlet, redirect, Scripts, useRouter } from "@tanstack/react-router";
import css from "../styles.css?url";
import { onUnauthorized, readCookie } from "../lib/api.ts";
import { ended, loadSession, seedSession, setNavigator, type SessionState } from "../lib/session.ts";
import { sameOriginPath, RETURN_COOKIE, rememberReturn } from "../lib/redirect.ts";
import { INVITATION_STASH, unstashInvitation } from "../lib/onboarding.ts";
import { setupOpen } from "../lib/setup.ts";
import { OverlayHost, Toaster } from "../lib/overlay.tsx";
import { Announcer } from "../lib/announce.tsx";
import { setStrangling, strangled } from "../lib/owned.ts";
import { createIsomorphicFn } from "@tanstack/react-start";

// Whether the Nuxt process still serves the views this application has not taken over (server env, never a URL).
const legacyBehind = createIsomorphicFn().server(() => !!process.env.SENTINEL_LEGACY_ORIGIN).client(() => false);
import { ButtonLink, Empty } from "../components/ui.tsx";

const PUBLIC = new Set(["/login", "/register", "/verify-email", "/forgot-password", "/setup", "/invitations/accept"]);
const SIGNED_OUT_ONLY = new Set(["/login", "/register"]);

export type Theme = "light" | "dark" | null;

// The first render runs on the server with the browser's cookie, so a signed-out visitor is redirected before any page draws.
export const Route = createRootRoute({
  beforeLoad: async ({ location }) => {
    // A view still served by the legacy process is left with a full page load.
    if (typeof window !== "undefined" && document.documentElement.dataset.hydrated === "1" && strangled(location.pathname)) {
      window.location.assign(location.href);
      await new Promise(() => {});
    }
    const session = await loadSession();
    const me = session.me;
    const path = location.pathname;
    if (path === "/login" || path === "/setup") {
      const open = await setupOpen();
      if (path === "/setup") {
        if (!open) throw redirect({ href: me ? "/" : "/login", replace: true });
      } else if (open && !me) throw redirect({ href: "/setup", replace: true });
    }
    const search = location.search as Record<string, unknown>;
    if (SIGNED_OUT_ONLY.has(path) && me) throw redirect({ href: sameOriginPath(search.next), replace: true });
    // `/` is the public landing page for a visitor who is not signed in.
    if (!me && !PUBLIC.has(path) && path !== "/") {
      const full = path + (location.searchStr || "");
      throw redirect({ href: `/login?next=${encodeURIComponent(full)}` });
    }
    const theme = (await readCookie("sentinel-theme")) as Theme;
    return { session, theme: theme === "dark" || theme === "light" ? theme : null, legacy: legacyBehind() };
  },
  loader: ({ context }) => ({ session: context.session as SessionState, theme: context.theme as Theme, legacy: context.legacy as boolean }),
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { name: "referrer", content: "no-referrer" },
      { title: "Sentinel" },
    ],
    links: [{ rel: "stylesheet", href: css }, { rel: "icon", href: "data:," }],
  }),
  component: Root,
  notFoundComponent: NotFound,
  errorComponent: ({ error }) => <Problem message={(error as Error)?.message} />,
});

function Root() {
  const { session, theme, legacy } = Route.useLoaderData();
  seedSession(session);
  if (typeof window !== "undefined" && legacy) setStrangling(true);
  const router = useRouter();
  useEffect(() => {
    setNavigator((to, replace) => router.navigate({ href: to, replace }));
    onUnauthorized(() => { void ended("expired"); });
    // A link from the old single-page interface (`/#/runs/<id>`, what GitHub check runs point at) goes to the run.
    const legacy = location.hash.match(/^#\/runs\/(run_[0-9a-f-]{36})$/);
    if (legacy) void router.navigate({ href: `/runs/${legacy[1]}`, replace: true });
    // The server render may not get to clear the return cookie when it redirects, so it is cleared here.
    if (new RegExp(`(?:^|; )${RETURN_COOKIE}=`).test(document.cookie)) rememberReturn(null);
    try {
      const raw = sessionStorage.getItem(INVITATION_STASH);
      if (raw !== null && unstashInvitation(raw, Date.now()) === null) sessionStorage.removeItem(INVITATION_STASH);
    } catch { /* storage off: nothing was parked */ }
    // Client-side navigation moves focus to the new view's heading.
    let first = true;
    const off = router.subscribe("onResolved", () => {
      if (first) { first = false; return; }
      requestAnimationFrame(() => {
        const heading = document.querySelector<HTMLElement>("main h1, h1");
        if (!heading) return;
        heading.tabIndex = -1;
        heading.focus({ preventScroll: true });
      });
    });
    document.documentElement.dataset.hydrated = "1";
    return () => { off(); onUnauthorized(null); };
  }, [router]);
  return (
    <Document theme={theme}>
      <Outlet />
      <OverlayHost />
      <Toaster />
      <Announcer />
    </Document>
  );
}

function Document({ theme, children }: { theme: Theme; children: ReactNode }) {
  return (
    <html lang="en" data-app="start" className={theme ?? undefined}>
      <head>
        <HeadContent />
      </head>
      <body className="min-h-screen bg-canvas text-fg antialiased">
        {children}
        <Scripts />
      </body>
    </html>
  );
}

// A refusal or a missing page, in words: the controller answers the same "not found" for what does not exist and what the caller may not see.
function NotFound() {
  return <Problem notFound />;
}

function Problem({ notFound, message }: { notFound?: boolean; message?: string }) {
  const [, setTick] = useState(0);
  useEffect(() => setTick(1), []);
  return (
    <main id="main" className="flex min-h-screen items-center justify-center p-4">
      <div className="w-full max-w-lg">
        <Empty headingLevel={1} icon={notFound ? "search-x" : "triangle-alert"} title={notFound ? "Not found" : "Something went wrong"}
          description={notFound ? "It does not exist, or you no longer have access to it." : message || "The page could not be shown."}
          actions={<ButtonLink to="/" icon="house" label="Back to your tenants" />} />
      </div>
    </main>
  );
}
