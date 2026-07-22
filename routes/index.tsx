import { AlertTriangle, GitBranch, Server, Shield } from "lucide-preact";
import { Head } from "fresh/runtime";
import { page } from "fresh";
import { Button } from "../components/Button.tsx";
import { EmptyState } from "../components/EmptyState.tsx";
import { Panel } from "../components/Panel.tsx";
import SystemStats from "../islands/SystemStats.tsx";
import RunnerGrid from "../islands/RunnerGrid.tsx";
import RunsTable from "../islands/RunsTable.tsx";
import SecurityFeed from "../islands/SecurityFeed.tsx";
import ProductTour from "../islands/ProductTour.tsx";
import {
  loadRunnersWithServices,
  loadSystemMetrics,
  type RunnerWithService,
} from "../lib/dashboard.ts";
import { githubOrg } from "../lib/env.ts";
import {
  GitHubApiError,
  listRecentOrgRuns,
  type WorkflowRun,
} from "../lib/github.ts";
import type { SystemMetrics } from "../lib/system.ts";
import {
  isVigilConfigured,
  loadSecuritySnapshot,
  type VigilSecuritySnapshot,
} from "../lib/vigil.ts";
import { define } from "../utils.ts";

type HomeData = {
  org: string;
  system: SystemMetrics | null;
  systemError: string | null;
  runners: RunnerWithService[];
  expectedCount: number;
  runnersError: string | null;
  runs: WorkflowRun[];
  runsError: string | null;
  vigilConfigured: boolean;
  security: VigilSecuritySnapshot | null;
};

export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return ctx.redirect("/auth/login");
    }

    const org = githubOrg();
    const vigilConfigured = isVigilConfigured();
    const [systemRes, runnersRes, runsSettled, security] = await Promise.all([
      loadSystemMetrics(),
      loadRunnersWithServices(),
      listRecentOrgRuns({ limit: 12 }).then(
        (runs) => ({ runs, error: null as string | null }),
        (err) => ({
          runs: [] as WorkflowRun[],
          error: err instanceof GitHubApiError
            ? err.message
            : err instanceof Error
            ? err.message
            : "Failed to list runs",
        }),
      ),
      vigilConfigured ? loadSecuritySnapshot(5) : Promise.resolve(null),
    ]);

    return page(
      {
        org,
        system: systemRes.data,
        systemError: systemRes.error,
        runners: runnersRes.data?.runners ?? [],
        expectedCount: runnersRes.data?.expectedCount ?? 0,
        runnersError: runnersRes.error,
        runs: runsSettled.runs,
        runsError: runsSettled.error,
        vigilConfigured,
        security,
      } satisfies HomeData,
    );
  },
});

export default define.page<typeof handler>(function Home({ data }) {
  const {
    org,
    system,
    systemError,
    runners,
    expectedCount,
    runnersError,
    runs,
    runsError,
    vigilConfigured,
    security,
  } = data;

  const online = runners.filter((r) => r.status === "online").length;
  const busy = runners.filter((r) => r.busy).length;

  return (
    <>
      <Head>
        <title>Dashboard · Sentinel</title>
      </Head>

      <ProductTour showBanner />

      <div class="fade-rise flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 class="font-sans text-lg font-semibold tracking-tight text-fg-strong sm:text-xl">
            Dashboard
          </h1>
          <p class="mt-0.5 text-sm text-muted">
            {org} · runners, host resources, and recent workflow runs
          </p>
        </div>
        <p class="font-mono text-xs text-subtle">
          {runners.length}/{expectedCount || "-"} registered
          {busy > 0 ? ` · ${busy} busy` : ""}
        </p>
      </div>

      <div class="fade-rise-delay grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Panel tone="subtle" title="Runners" class="!p-4">
          {runnersError
            ? (
              <EmptyState
                tone="error"
                title="Runners unavailable"
                description={runnersError}
                icon={<AlertTriangle class="size-4" aria-hidden="true" />}
              />
            )
            : (
              <div class="space-y-3">
                <div class="flex items-center gap-2 text-muted">
                  <Server class="size-4" aria-hidden="true" />
                  <span class="font-mono text-2xl font-semibold tabular-nums text-fg-strong">
                    {online}
                  </span>
                  <span class="text-sm text-muted">online</span>
                </div>
                <p class="font-mono text-xs text-subtle">
                  {runners.length} total
                  {expectedCount > 0 ? ` · expect ${expectedCount}` : ""}
                  {busy > 0 ? ` · ${busy} busy` : ""}
                </p>
                <Button href="/runners" variant="secondary" class="!py-1.5">
                  View runners
                </Button>
              </div>
            )}
        </Panel>

        <Panel
          tone="subtle"
          title="System"
          class="!p-4"
          data-tour="system"
        >
          <SystemStats
            initialSystem={system}
            initialError={systemError}
          />
        </Panel>

        <Panel tone="subtle" title="Runs" class="!p-4">
          {runsError
            ? (
              <EmptyState
                tone="error"
                title="Runs unavailable"
                description={runsError}
                icon={<GitBranch class="size-4" aria-hidden="true" />}
              />
            )
            : (
              <div class="space-y-3">
                <div class="flex items-center gap-2 text-muted">
                  <GitBranch class="size-4" aria-hidden="true" />
                  <span class="font-mono text-2xl font-semibold tabular-nums text-fg-strong">
                    {runs.length}
                  </span>
                  <span class="text-sm text-muted">recent</span>
                </div>
                <p class="font-mono text-xs text-subtle">
                  Across org repositories
                </p>
                <Button href="/runs" variant="secondary" class="!py-1.5">
                  View runs
                </Button>
              </div>
            )}
        </Panel>
      </div>

      {vigilConfigured && (
        <Panel
          title="Security"
          subtitle="Vigil SOC summary"
          data-tour="security"
          actions={
            <Button
              href="/security"
              variant="ghost"
              class="!px-2 !py-1 text-xs"
            >
              <Shield class="size-3.5" aria-hidden="true" />
              Overview
            </Button>
          }
          class="fade-rise-delay"
        >
          <SecurityFeed
            variant="strip"
            limit={5}
            initial={security}
          />
        </Panel>
      )}

      <Panel
        title="Runners"
        subtitle="Self-hosted org runners and local service state"
        data-tour="runners"
        actions={
          <Button href="/runners" variant="ghost" class="!px-2 !py-1 text-xs">
            Details
          </Button>
        }
        class="fade-rise-delay"
      >
        <RunnerGrid
          org={org}
          initialRunners={runners}
          expectedCount={expectedCount}
          initialError={runnersError}
        />
      </Panel>

      <Panel
        title="Recent runs"
        subtitle="Newest workflow runs across the org"
        data-tour="runs"
        actions={
          <Button href="/runs" variant="ghost" class="!px-2 !py-1 text-xs">
            All runs
          </Button>
        }
        class="fade-rise-delay"
      >
        <RunsTable
          initialRuns={runs}
          initialError={runsError}
          limit={12}
          compact
        />
      </Panel>
    </>
  );
});
