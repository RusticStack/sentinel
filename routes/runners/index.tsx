import { Head } from "fresh/runtime";
import { page } from "fresh";
import RunnerGrid from "../../islands/RunnerGrid.tsx";
import {
  loadRunnersWithServices,
  type RunnerWithService,
} from "../../lib/dashboard.ts";
import { githubOrg } from "../../lib/env.ts";
import { define } from "../../utils.ts";

type RunnersPageData = {
  org: string;
  runners: RunnerWithService[];
  expectedCount: number;
  error: string | null;
  focusId: number | null;
};

export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return ctx.redirect("/auth/login");
    }

    const idRaw = ctx.url.searchParams.get("id")?.trim();
    const focusId = idRaw && /^\d+$/.test(idRaw)
      ? Number.parseInt(idRaw, 10)
      : null;

    const result = await loadRunnersWithServices();
    return page(
      {
        org: githubOrg(),
        runners: result.data?.runners ?? [],
        expectedCount: result.data?.expectedCount ?? 0,
        error: result.error,
        focusId,
      } satisfies RunnersPageData,
    );
  },
});

export default define.page<typeof handler>(function RunnersPage({ data }) {
  const { org, runners, expectedCount, error, focusId } = data;

  return (
    <>
      <Head>
        <title>Runners · Sentinel</title>
      </Head>

      <div class="fade-rise flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 class="font-sans text-lg font-semibold tracking-tight text-fg-strong sm:text-xl">
            Runners
          </h1>
          <p class="mt-0.5 text-sm text-muted">
            Per-runner detail for {org} self-hosted Actions runners
          </p>
        </div>
        <p class="font-mono text-xs text-subtle">
          {runners.length} registered
          {expectedCount > 0 ? ` · expect ${expectedCount}` : ""}
        </p>
      </div>

      <div class="fade-rise-delay">
        <RunnerGrid
          org={org}
          initialRunners={runners}
          expectedCount={expectedCount}
          initialError={error}
          focusId={focusId}
          showDetails
        />
      </div>
    </>
  );
});
