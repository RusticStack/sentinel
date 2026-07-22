/**
 * Pure workflow-run filters: safe for islands (no Deno / env imports).
 */
import type { WorkflowRun } from "./github.ts";

export function filterRuns(
  runs: WorkflowRun[],
  filters: { status?: string; repo?: string },
): WorkflowRun[] {
  let out = runs;
  const repo = filters.repo?.trim();
  if (repo) {
    const needle = repo.toLowerCase();
    out = out.filter((r) =>
      r.repository.toLowerCase() === needle ||
      r.repository.toLowerCase().endsWith(`/${needle}`) ||
      r.repository.toLowerCase().includes(needle)
    );
  }
  const status = filters.status?.trim().toLowerCase();
  if (status && status !== "all") {
    out = out.filter((r) => {
      const conclusion = (r.conclusion ?? "").toLowerCase();
      const runStatus = (r.status ?? "").toLowerCase();
      if (status === "in_progress") {
        return runStatus === "in_progress" || runStatus === "queued" ||
          runStatus === "pending" || runStatus === "waiting";
      }
      if (status === "completed") {
        return runStatus === "completed";
      }
      // Match conclusion (success, failure, cancelled, …)
      return conclusion === status;
    });
  }
  return out;
}
