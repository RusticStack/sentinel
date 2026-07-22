/**
 * Shared SSR loaders for dashboard pages: call lib/* directly (never /api/*).
 */
import { GitHubApiError, listOrgRunners, type OrgRunner } from "./github.ts";
import { runnerCount } from "./env.ts";
import { filterRuns } from "./runs_filter.ts";
import { recordMetricSample } from "./metric_history.ts";
import {
  getServiceStatus,
  getSystemMetrics,
  runnerServiceUnit,
  type ServiceStatus,
  type SystemMetricsPayload,
} from "./system.ts";

export type RunnerWithService = OrgRunner & { service: ServiceStatus };

export { filterRuns };

export type LoadResult<T> = {
  data: T | null;
  error: string | null;
};

export async function loadSystemMetrics(): Promise<
  LoadResult<SystemMetricsPayload>
> {
  try {
    const metrics = await getSystemMetrics();
    let history: SystemMetricsPayload["history"];
    try {
      history = await recordMetricSample(metrics);
    } catch {
      history = undefined;
    }
    return { data: { ...metrics, history }, error: null };
  } catch (err) {
    return {
      data: null,
      error: err instanceof Error
        ? err.message
        : "Failed to load system metrics",
    };
  }
}

export async function loadRunnersWithServices(): Promise<
  LoadResult<{
    runners: RunnerWithService[];
    expectedCount: number;
    totalCount: number;
  }>
> {
  try {
    const runners = await listOrgRunners();
    const withServices: RunnerWithService[] = await Promise.all(
      runners.map(async (runner) => {
        const unit = runnerServiceUnit(runner.name);
        const service = await getServiceStatus(unit);
        return { ...runner, service };
      }),
    );
    return {
      data: {
        runners: withServices,
        expectedCount: runnerCount(),
        totalCount: withServices.length,
      },
      error: null,
    };
  } catch (err) {
    const message = err instanceof GitHubApiError
      ? err.message
      : err instanceof Error
      ? err.message
      : "Failed to list runners";
    return { data: null, error: message };
  }
}
