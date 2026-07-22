import {
  GitHubApiError,
  listRecentOrgRuns,
  listRepoRuns,
  listRunJobs,
} from "../../lib/github.ts";
import { parseRepoName, REPO_NAME_MAX_LENGTH } from "../../lib/validate.ts";
import { define } from "../../utils.ts";

/**
 * GET /api/runs: recent workflow runs across the org (or one repo).
 * Query:
 *   - `repo`: limit to one bare repo name (allowlisted)
 *   - `run_id`: with `repo`, return jobs for that run
 *   - `limit`: max aggregated runs (default 30)
 * Auth-gated by middleware (401 JSON if unauthenticated).
 */
export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const url = ctx.url;
    const repoRaw = url.searchParams.get("repo");
    const repoRequested = repoRaw != null && repoRaw.trim() !== "";
    const repo = repoRequested ? parseRepoName(repoRaw) : null;
    if (repoRequested && !repo) {
      return Response.json(
        {
          error:
            `Invalid repo: must be a bare repository name (A-Z, a-z, 0-9, ., _, -; max ${REPO_NAME_MAX_LENGTH} characters)`,
        },
        { status: 400 },
      );
    }
    const runIdRaw = url.searchParams.get("run_id")?.trim();
    const limitRaw = url.searchParams.get("limit")?.trim();
    const limit = limitRaw ? Number.parseInt(limitRaw, 10) : 30;

    try {
      if (repo && runIdRaw) {
        const runId = Number.parseInt(runIdRaw, 10);
        if (!Number.isFinite(runId) || runId <= 0) {
          return Response.json(
            { error: "Invalid run_id" },
            { status: 400 },
          );
        }
        const jobs = await listRunJobs(repo, runId);
        return Response.json({
          repo,
          runId,
          totalCount: jobs.length,
          jobs,
        });
      }

      if (repo) {
        const runs = await listRepoRuns(repo, {
          perPage: Number.isFinite(limit) && limit > 0
            ? Math.min(limit, 100)
            : 5,
        });
        return Response.json({
          totalCount: runs.length,
          runs,
        });
      }

      const runs = await listRecentOrgRuns({
        limit: Number.isFinite(limit) && limit > 0 ? Math.min(limit, 100) : 30,
      });
      return Response.json({
        totalCount: runs.length,
        runs,
      });
    } catch (err) {
      if (err instanceof GitHubApiError) {
        const status = err.status >= 400 && err.status < 600 ? err.status : 502;
        return Response.json({ error: err.message }, { status });
      }
      const message = err instanceof Error
        ? err.message
        : "Failed to list runs";
      return Response.json({ error: message }, { status: 502 });
    }
  },
});
