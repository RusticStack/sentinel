import { Head } from "fresh/runtime";
import { page } from "fresh";
import { Button } from "../../components/Button.tsx";
import { Panel } from "../../components/Panel.tsx";
import RunsTable from "../../islands/RunsTable.tsx";
import { filterRuns } from "../../lib/dashboard.ts";
import { githubOrg } from "../../lib/env.ts";
import {
  GitHubApiError,
  listOrgRepos,
  listRecentOrgRuns,
  type OrgRepo,
  type WorkflowRun,
} from "../../lib/github.ts";
import { parseRepoName } from "../../lib/validate.ts";
import { define } from "../../utils.ts";

const STATUS_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "in_progress", label: "In progress" },
  { value: "completed", label: "Completed" },
  { value: "success", label: "Success" },
  { value: "failure", label: "Failure" },
  { value: "cancelled", label: "Cancelled" },
] as const;

type RunsPageData = {
  org: string;
  runs: WorkflowRun[];
  filtered: WorkflowRun[];
  repos: OrgRepo[];
  error: string | null;
  filters: { status: string; repo: string };
};

function sanitizeRepoFilter(raw: string | null): string {
  // Same allowlist as /api/runs; invalid values are ignored for SSR filters.
  return parseRepoName(raw) ?? "";
}

function sanitizeStatusFilter(raw: string | null): string {
  if (!raw) return "all";
  const value = raw.trim().toLowerCase();
  const allowed = STATUS_OPTIONS.map((o) => o.value);
  return (allowed as string[]).includes(value) ? value : "all";
}

export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return ctx.redirect("/auth/login");
    }

    const status = sanitizeStatusFilter(ctx.url.searchParams.get("status"));
    const repo = sanitizeRepoFilter(ctx.url.searchParams.get("repo"));

    try {
      const [runs, repos] = await Promise.all([
        listRecentOrgRuns({ limit: 50 }),
        listOrgRepos(),
      ]);
      const filtered = filterRuns(runs, {
        status: status === "all" ? undefined : status,
        repo: repo || undefined,
      });
      return page(
        {
          org: githubOrg(),
          runs,
          filtered,
          repos,
          error: null,
          filters: { status, repo },
        } satisfies RunsPageData,
      );
    } catch (err) {
      const message = err instanceof GitHubApiError
        ? err.message
        : err instanceof Error
        ? err.message
        : "Failed to list runs";
      return page(
        {
          org: githubOrg(),
          runs: [],
          filtered: [],
          repos: [],
          error: message,
          filters: { status, repo },
        } satisfies RunsPageData,
      );
    }
  },
});

export default define.page<typeof handler>(function RunsPage({ data }) {
  const { org, runs, filtered, repos, error, filters } = data;
  const hasFilters = filters.status !== "all" || filters.repo.length > 0;

  return (
    <>
      <Head>
        <title>Runs · Sentinel</title>
      </Head>

      <div class="fade-rise flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 class="font-sans text-lg font-semibold tracking-tight text-fg-strong sm:text-xl">
            Workflow runs
          </h1>
          <p class="mt-0.5 text-sm text-muted">
            Recent Actions runs across {org}
          </p>
        </div>
        <p class="font-mono text-xs text-subtle">
          {filtered.length} shown
        </p>
      </div>

      <Panel
        title="Filters"
        subtitle="Server-rendered: submit reloads the table"
        class="fade-rise-delay"
      >
        <form
          method="get"
          action="/runs"
          class="flex flex-wrap items-end gap-3"
          aria-label="Filter workflow runs"
        >
          <div class="form-field flex-1">
            <label class="form-label" htmlFor="runs-filter-status">
              Status
            </label>
            <select
              id="runs-filter-status"
              name="status"
              class="filter-control"
              value={filters.status}
            >
              {STATUS_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div class="form-field flex-[2]">
            <label class="form-label" htmlFor="runs-filter-repo">
              Repository
            </label>
            <select
              id="runs-filter-repo"
              name="repo"
              class="filter-control"
              value={filters.repo}
            >
              <option value="">All repositories</option>
              {repos.map((r) => (
                <option key={r.id} value={r.name}>
                  {r.name}
                </option>
              ))}
            </select>
          </div>

          <div class="flex gap-2">
            <Button type="submit" variant="primary">
              Apply
            </Button>
            {hasFilters && (
              <Button href="/runs" variant="secondary">
                Clear
              </Button>
            )}
          </div>
        </form>
      </Panel>

      <Panel title="Runs" class="fade-rise-delay">
        <RunsTable
          initialRuns={runs}
          initialError={error}
          filters={{
            status: filters.status,
            repo: filters.repo || undefined,
          }}
        />
      </Panel>
    </>
  );
});
