import { BookOpen, HelpCircle, Shield } from "lucide-preact";
import { Head } from "fresh/runtime";
import { page } from "fresh";
import { Panel } from "../components/Panel.tsx";
import { Button } from "../components/Button.tsx";
import { TOUR_QUERY } from "../lib/tour.ts";
import { optionalEnv } from "../lib/env.ts";
import { define } from "../utils.ts";

export const handler = define.handlers({
  GET(ctx) {
    if (!ctx.state.user) {
      return ctx.redirect("/auth/login");
    }
    return page({
      vigilConfigured: Boolean(optionalEnv("VIGIL_URL")),
    });
  },
});

export default define.page<typeof handler>(function HelpPage({ data }) {
  const { vigilConfigured } = data;

  return (
    <>
      <Head>
        <title>Help · Sentinel</title>
      </Head>

      <div class="fade-rise flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 class="font-sans text-lg font-semibold tracking-tight text-fg-strong sm:text-xl">
            Help
          </h1>
          <p class="mt-0.5 text-sm text-muted">
            How Sentinel works: auth, runners, runs
            {vigilConfigured ? ", and Vigil" : ""}
          </p>
        </div>
      </div>

      <Panel
        title="Dashboard tour"
        subtitle="A short walkthrough of the main regions"
        actions={
          <Button href={`/?${TOUR_QUERY}=1`} variant="primary" data-tour-replay>
            Replay tour
          </Button>
        }
        class="fade-rise-delay"
      >
        <p class="text-sm leading-relaxed text-muted">
          The tour highlights navigation, host resources, runners, and workflow
          runs
          {vigilConfigured
            ? ", plus the Security panel when Vigil is connected"
            : ""}
          . First-time guidance on the Dashboard can be dismissed; replaying
          here does not change your session.
        </p>
      </Panel>

      <div class="fade-rise-delay grid gap-5 lg:grid-cols-2">
        <Panel
          title="Sign-in & access"
          subtitle="Org members only"
        >
          <ul class="space-y-3 text-sm leading-relaxed text-muted">
            <li class="flex gap-2.5">
              <HelpCircle
                class="mt-0.5 size-4 shrink-0 text-accent-muted"
                aria-hidden="true"
              />
              <span>
                Sign in with GitHub using{" "}
                <span class="font-mono text-fg">read:org</span>. Only active
                members of your configured org can open the dashboard.
              </span>
            </li>
            <li class="flex gap-2.5">
              <HelpCircle
                class="mt-0.5 size-4 shrink-0 text-accent-muted"
                aria-hidden="true"
              />
              <span>
                Sessions live server-side. Logout ends the session immediately;
                leaving the org stops access within a few minutes.
              </span>
            </li>
          </ul>
        </Panel>

        <Panel
          title="Runners & workflow runs"
          subtitle="Operational terms"
        >
          <ul class="space-y-3 text-sm leading-relaxed text-muted">
            <li class="flex gap-2.5">
              <BookOpen
                class="mt-0.5 size-4 shrink-0 text-accent-muted"
                aria-hidden="true"
              />
              <span>
                A <strong class="font-medium text-fg">runner</strong>{" "}
                is a self-hosted GitHub Actions machine registered to your org.
                Status comes from GitHub; local service state uses systemd when
                Sentinel runs on the host.
              </span>
            </li>
            <li class="flex gap-2.5">
              <BookOpen
                class="mt-0.5 size-4 shrink-0 text-accent-muted"
                aria-hidden="true"
              />
              <span>
                A <strong class="font-medium text-fg">workflow run</strong>{" "}
                is an Actions execution. Open a row to view details on GitHub.
                Filters on the Runs page are applied server-side.
              </span>
            </li>
          </ul>
        </Panel>
      </div>

      {vigilConfigured && (
        <Panel
          title="Security (Vigil)"
          subtitle="Optional SOC integration"
          class="fade-rise-delay"
        >
          <div class="flex gap-2.5 text-sm leading-relaxed text-muted">
            <Shield
              class="mt-0.5 size-4 shrink-0 text-accent-muted"
              aria-hidden="true"
            />
            <p>
              When Vigil is configured, the Security tab surfaces findings,
              cases, and agents from the Vigil backend. Credentials stay
              server-side; the browser only sees summarized data through
              Sentinel APIs.
            </p>
          </div>
        </Panel>
      )}

      <Panel
        title="Ops & deploy"
        subtitle="Further reading"
        class="fade-rise-delay"
      >
        <p class="text-sm leading-relaxed text-muted">
          For environment variables, reverse proxy, and systemd setup, see the
          project README and{" "}
          <span class="font-mono text-xs text-fg">docs/DEPLOY.md</span>{" "}
          in the Sentinel repository. This Help page covers day-to-day dashboard
          use only.
        </p>
      </Panel>
    </>
  );
});
