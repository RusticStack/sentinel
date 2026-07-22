import { GitHubApiError, listOrgRunners } from "../../lib/github.ts";
import { runnerCount } from "../../lib/env.ts";
import { getServiceStatus, runnerServiceUnit } from "../../lib/system.ts";
import { define } from "../../utils.ts";

/**
 * GET /api/runners: org self-hosted runners + local systemd status.
 * Auth-gated by middleware (401 JSON if unauthenticated).
 */
export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    try {
      const runners = await listOrgRunners();
      const withServices = await Promise.all(
        runners.map(async (runner) => {
          const unit = runnerServiceUnit(runner.name);
          const service = await getServiceStatus(unit);
          return { ...runner, service };
        }),
      );

      return Response.json({
        expectedCount: runnerCount(),
        totalCount: withServices.length,
        runners: withServices,
      });
    } catch (err) {
      if (err instanceof GitHubApiError) {
        const status = err.status >= 400 && err.status < 600 ? err.status : 502;
        return Response.json({ error: err.message }, { status });
      }
      const message = err instanceof Error
        ? err.message
        : "Failed to list runners";
      return Response.json({ error: message }, { status: 502 });
    }
  },
});
