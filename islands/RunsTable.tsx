import { useEffect, useMemo, useState } from "preact/hooks";
import { AlertTriangle, GitBranch } from "lucide-preact";
import { Button } from "../components/Button.tsx";
import { DataTable } from "../components/DataTable.tsx";
import { EmptyState } from "../components/EmptyState.tsx";
import { StatusBadge } from "../components/StatusBadge.tsx";
import { subscribeLiveFeed } from "../lib/live_feed.ts";
import { QuietLiveRegion, useRetryFeedback } from "../lib/quiet_refresh.tsx";
import { filterRuns } from "../lib/runs_filter.ts";
import {
  formatRelativeTime,
  shortSha,
  workflowRunLabel,
  workflowRunTone,
} from "../lib/format.ts";
import type { WorkflowRun } from "../lib/github.ts";

export type RunsTableProps = {
  initialRuns: WorkflowRun[];
  initialError: string | null;
  /** Limit rows after filter (dashboard preview). */
  limit?: number;
  filters?: { status?: string; repo?: string };
  /** Compact columns for the home dashboard. */
  compact?: boolean;
};

async function fetchRuns(): Promise<
  { ok: true; data: WorkflowRun[] } | { ok: false; error: string }
> {
  try {
    const res = await fetch("/api/runs?limit=50", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      let message = `HTTP ${res.status}`;
      try {
        const body = await res.json() as { error?: string };
        if (body?.error) message = body.error;
      } catch {
        // ignore
      }
      return { ok: false, error: message };
    }
    const body = await res.json() as { runs?: WorkflowRun[] };
    return { ok: true, data: body.runs ?? [] };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Network error",
    };
  }
}

/** Auto-refreshing runs table (WS first, `/api/runs` poll fallback). */
export default function RunsTable(props: RunsTableProps) {
  const [runs, setRuns] = useState(props.initialRuns);
  const [error, setError] = useState(props.initialError);
  const [retrying, setRetrying] = useState(false);
  const { flashClass, liveMessage, markUpdated } = useRetryFeedback();
  const filters = props.filters ?? {};
  const limit = props.limit;
  const compact = props.compact ?? false;

  useEffect(() => {
    return subscribeLiveFeed((snap) => {
      if (snap.errors?.runs && !snap.runs) {
        setError(snap.errors.runs);
        return;
      }
      if (snap.runs) {
        setRuns(snap.runs.runs);
        setError(null);
      }
    });
  }, []);

  const retry = async () => {
    setRetrying(true);
    const result = await fetchRuns();
    setRetrying(false);
    if (result.ok) {
      setRuns(result.data);
      setError(null);
      markUpdated();
    } else {
      setError(result.error);
    }
  };

  const filtered = useMemo(() => {
    let list = filterRuns(runs, {
      status: filters.status,
      repo: filters.repo,
    });
    if (limit != null && limit > 0) {
      list = list.slice(0, limit);
    }
    return list;
  }, [runs, filters.status, filters.repo, limit]);

  const retryAction = (
    <Button
      type="button"
      variant="secondary"
      class="!py-1.5"
      disabled={retrying}
      onClick={retry}
    >
      {retrying ? "Retrying…" : "Retry"}
    </Button>
  );

  if (error) {
    return (
      <EmptyState
        tone="error"
        title="Could not load runs"
        description={error}
        icon={<AlertTriangle class="size-4" aria-hidden="true" />}
        action={retryAction}
      />
    );
  }

  if (filtered.length === 0) {
    const hasFilters = Boolean(
      (filters.status && filters.status !== "all") || filters.repo,
    );
    return (
      <EmptyState
        title={hasFilters ? "No matching runs" : "No recent runs"}
        description={hasFilters
          ? "Try clearing filters or picking another repository."
          : "Workflow runs will appear here once repositories start executing Actions."}
        icon={<GitBranch class="size-4" aria-hidden="true" />}
        action={hasFilters ? undefined : retryAction}
      />
    );
  }

  const table = compact
    ? (
      <DataTable
        dense
        caption="Recent workflow runs"
        columns={[
          { key: "workflow", header: "Workflow" },
          { key: "repo", header: "Repo" },
          { key: "branch", header: "Branch", hideBelow: "md" },
          { key: "status", header: "Status" },
          { key: "when", header: "When", align: "end", hideBelow: "sm" },
        ]}
        rows={filtered.map((run) => ({
          key: String(run.id),
          href: run.htmlUrl,
          cells: {
            workflow: (
              <span class="font-medium">
                {run.name ?? run.path}
                <span class="ml-1.5 font-mono text-[0.65rem] text-subtle">
                  #{run.runNumber}
                </span>
              </span>
            ),
            repo: (
              <span class="font-mono text-xs text-muted">
                {run.repository.split("/").pop() ?? run.repository}
              </span>
            ),
            branch: (
              <span class="font-mono text-xs">
                {run.headBranch ?? "-"}
                <span class="ml-1.5 text-subtle">
                  {shortSha(run.headSha)}
                </span>
              </span>
            ),
            status: (
              <StatusBadge
                tone={workflowRunTone(run.status, run.conclusion)}
              >
                {workflowRunLabel(run.status, run.conclusion)}
              </StatusBadge>
            ),
            when: (
              <span class="font-mono text-xs text-muted">
                {formatRelativeTime(run.updatedAt)}
              </span>
            ),
          },
        }))}
      />
    )
    : (
      <DataTable
        caption="Workflow runs"
        columns={[
          { key: "workflow", header: "Workflow" },
          { key: "repo", header: "Repository", hideBelow: "sm" },
          { key: "branch", header: "Branch", hideBelow: "md" },
          { key: "event", header: "Event", hideBelow: "lg" },
          { key: "actor", header: "Actor", hideBelow: "lg" },
          { key: "status", header: "Status" },
          { key: "when", header: "Updated", align: "end", hideBelow: "sm" },
        ]}
        rows={filtered.map((run) => ({
          key: String(run.id),
          href: run.htmlUrl,
          cells: {
            workflow: (
              <span class="font-medium">
                {run.name ?? run.path}
                <span class="ml-1.5 font-mono text-[0.65rem] text-subtle">
                  #{run.runNumber}
                </span>
              </span>
            ),
            repo: (
              <span class="font-mono text-xs text-muted">
                {run.repository}
              </span>
            ),
            branch: (
              <span class="font-mono text-xs">
                {run.headBranch ?? "-"}
                <span class="ml-1.5 text-subtle">
                  {shortSha(run.headSha)}
                </span>
              </span>
            ),
            event: (
              <span class="font-mono text-xs text-muted">
                {run.event}
              </span>
            ),
            actor: (
              <span class="font-mono text-xs text-muted">
                {run.actorLogin ?? "-"}
              </span>
            ),
            status: (
              <StatusBadge
                tone={workflowRunTone(run.status, run.conclusion)}
              >
                {workflowRunLabel(run.status, run.conclusion)}
              </StatusBadge>
            ),
            when: (
              <span class="font-mono text-xs text-muted">
                {formatRelativeTime(run.updatedAt)}
              </span>
            ),
          },
        }))}
      />
    );

  return (
    <div class={flashClass}>
      <QuietLiveRegion message={liveMessage} />
      {table}
    </div>
  );
}
