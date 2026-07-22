/**
 * Build auth-gated realtime snapshots for WebSocket push.
 * Server-only (uses Deno env + GitHub/system collectors + optional Vigil).
 */
import { loadRunnersWithServices, loadSystemMetrics } from "./dashboard.ts";
import {
  GitHubApiError,
  listRecentOrgRuns,
  type WorkflowRun,
} from "./github.ts";
import type { SnapshotMessage, VigilRealtimeSlice } from "./realtime.ts";
import { loadSecuritySnapshot } from "./vigil.ts";

const RUNS_LIMIT = 50;

export async function buildRealtimeSnapshot(): Promise<SnapshotMessage> {
  const [systemRes, runnersRes, runsSettled, vigilSnap] = await Promise.all([
    loadSystemMetrics(),
    loadRunnersWithServices(),
    listRecentOrgRuns({ limit: RUNS_LIMIT }).then(
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
    loadSecuritySnapshot(8),
  ]);

  const errors: SnapshotMessage["errors"] = {};
  if (systemRes.error) errors.system = systemRes.error;
  if (runnersRes.error) errors.runners = runnersRes.error;
  if (runsSettled.error) errors.runs = runsSettled.error;

  let vigil: VigilRealtimeSlice | null = null;
  if (vigilSnap) {
    vigil = {
      enabled: true,
      findingsTotal: vigilSnap.findingsTotal,
      criticalCount: vigilSnap.criticalCount,
      highCount: vigilSnap.highCount,
      casesTotal: vigilSnap.casesTotal,
      activeCases: vigilSnap.activeCases,
      agentsCount: vigilSnap.agentsCount,
      recentFindings: vigilSnap.recentFindings,
      error: vigilSnap.error,
    };
  }

  return {
    type: "snapshot",
    ts: Date.now(),
    system: systemRes.data,
    runners: runnersRes.data,
    runs: {
      totalCount: runsSettled.runs.length,
      runs: runsSettled.runs,
    },
    vigil,
    errors: Object.keys(errors).length > 0 ? errors : undefined,
  };
}
