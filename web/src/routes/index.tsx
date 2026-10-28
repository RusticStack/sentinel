// `/`: the public landing page for a visitor; a signed-in person goes on to a pending return, the last tenant used or the first one.
import { createFileRoute, redirect } from "@tanstack/react-router";
import { readCookie } from "../lib/api.ts";
import { pendingReturn, RETURN_COOKIE } from "../lib/redirect.ts";
import type { SessionState } from "../lib/session.ts";
import { useSession } from "../lib/session.ts";
import { ButtonLink, Empty, Icon } from "../components/ui.tsx";

export const Route = createFileRoute("/")({
  beforeLoad: async ({ context }) => {
    const { me, tenants } = (context as { session: SessionState }).session;
    if (!me) return;
    // A return left pending by a round trip out of the interface (e.g. GitHub sign-in) wins over the last tenant.
    const dest = pendingReturn(await readCookie(RETURN_COOKIE));
    if (dest) throw redirect({ href: dest, replace: true });
    const last = await readCookie("sentinel-tenant");
    const target = tenants.find((t) => t.slug === last) ?? tenants[0];
    if (target) throw redirect({ to: "/t/$slug", params: { slug: target.slug }, replace: true });
  },
  head: () => ({ meta: [{ title: "Sentinel" }] }),
  component: Home,
});

function Home() {
  const { me } = useSession();
  if (me) {
    return (
      <main id="main" className="mx-auto max-w-2xl p-6">
        <Empty headingLevel={1} icon="building-2" title="No organizations yet"
          description="Your account does not belong to any organization yet. Accept an invitation from your email, create an organization if this instance allows it, or link GitHub to join one whose membership GitHub manages."
          actions={<>
            <ButtonLink to="/organizations" icon="building" label="Organizations" />
            {me.super_admin ? <ButtonLink to="/platform" icon="shield" color="neutral" variant="outline" label="Open platform administration" /> : null}
          </>} />
      </main>
    );
  }
  return <Landing />;
}

const POINTS: [string, string, string][] = [
  ["play", "Native pipelines", "A .sentinel.yml runs on your own Linux workers in fresh rootless containers, with exact-revision checkouts and fenced leases."],
  ["scroll-text", "Logs that keep up", "Live, resumable log streams; a quarter-million lines held in the browser, indexed search and deep links to the failing line."],
  ["git-merge", "GitHub checks", "Pull requests and pushes trigger runs and get their required checks back, through one GitHub App."],
  ["server", "Your hardware", "Workers report capacity and caches; the queue says why a job waits. No cloud account and no external database."],
];

function Landing() {
  return (
    <main id="main" className="min-h-screen bg-canvas">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-5xl items-center justify-between gap-4 px-4 py-3">
          <span className="flex items-center gap-2 font-semibold text-strong"><Icon name="radar" className="size-5 text-primary" />Sentinel</span>
          <div className="flex gap-2">
            <ButtonLink to="/login" color="neutral" variant="ghost" label="Sign in" />
            <ButtonLink to="/register" label="Sign up" />
          </div>
        </div>
      </header>
      <section className="mx-auto max-w-5xl px-4 py-16" aria-labelledby="hero-h">
        <h1 id="hero-h" className="max-w-3xl text-3xl font-semibold tracking-tight text-strong sm:text-4xl">Continuous integration on your own machines, built to be fast.</h1>
        <p className="mt-4 max-w-2xl text-base text-muted">
          Sentinel is a self-hosted CI engine. Connect your GitHub organizations and accounts, run their pipelines on your workers, and follow every run, queue and worker from one place.
        </p>
        <div className="mt-8 flex flex-wrap gap-3">
          <ButtonLink to="/login" icon="log-in" label="Sign in" />
          <ButtonLink to="/register" color="neutral" variant="outline" label="Create an account" />
        </div>
      </section>
      <section className="border-t border-line bg-subtle" aria-labelledby="what-h">
        <div className="mx-auto max-w-5xl px-4 py-12">
          <h2 id="what-h" className="text-lg font-semibold text-strong">What it does</h2>
          <ul className="mt-6 grid gap-6 sm:grid-cols-2">
            {POINTS.map(([icon, title, text]) => (
              <li key={title} className="flex gap-3">
                <Icon name={icon} className="mt-0.5 size-5 text-primary" />
                <div><h3 className="font-medium text-strong">{title}</h3><p className="text-sm text-muted">{text}</p></div>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </main>
  );
}
