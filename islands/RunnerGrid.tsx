import { useEffect, useState } from "preact/hooks";
import { AlertTriangle, Server } from "lucide-preact";
import { Button } from "../components/Button.tsx";
import { EmptyState } from "../components/EmptyState.tsx";
import { Panel } from "../components/Panel.tsx";
import {
  RunnerCard,
  runnerStatusLabel,
  runnerStatusTone,
} from "../components/RunnerCard.tsx";
import { StatusBadge } from "../components/StatusBadge.tsx";
import { subscribeLiveFeed } from "../lib/live_feed.ts";
import { QuietLiveRegion, useRetryFeedback } from "../lib/quiet_refresh.tsx";
import type { RunnerWithService } from "../lib/realtime.ts";

export type RunnerGridProps = {
  org: string;
  initialRunners: RunnerWithService[];
  expectedCount: number;
  initialError: string | null;
  /** Deep-link focus from `/runners?id=` */
  focusId?: number | null;
  /** Show per-runner detail panels (runners page). */
  showDetails?: boolean;
};

function serviceMemoryLabel(bytes: number | null): string {
  if (bytes == null || !Number.isFinite(bytes) || bytes < 0) return "-";
  const mb = bytes / (1024 * 1024);
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`;
  return `${Math.round(mb)} MB`;
}

function RunnerDetail({ runner }: { runner: RunnerWithService }) {
  const service = runner.service;
  const labels = runner.labels.map((l) => l.name);

  return (
    <Panel
      title={runner.name}
      subtitle={`ID ${runner.id} · ${runner.os}${
        runner.ephemeral ? " · ephemeral" : ""
      }`}
      actions={
        <StatusBadge tone={runnerStatusTone(runner)}>
          {runnerStatusLabel(runner)}
        </StatusBadge>
      }
    >
      <div class="grid gap-6 sm:grid-cols-2">
        <div>
          <h3 class="font-sans text-xs font-semibold tracking-wide text-muted uppercase">
            GitHub
          </h3>
          <dl class="mt-3 space-y-2 font-mono text-sm">
            <div class="flex justify-between gap-3 border-b border-border-subtle/70 pb-2">
              <dt class="text-muted">Status</dt>
              <dd class="text-fg-strong">{runner.status}</dd>
            </div>
            <div class="flex justify-between gap-3 border-b border-border-subtle/70 pb-2">
              <dt class="text-muted">Busy</dt>
              <dd class="text-fg-strong">{runner.busy ? "yes" : "no"}</dd>
            </div>
            <div class="flex justify-between gap-3">
              <dt class="text-muted">Labels</dt>
              <dd class="max-w-[60%] text-end text-fg-strong">
                {labels.length > 0 ? labels.join(", ") : "-"}
              </dd>
            </div>
          </dl>
        </div>

        <div>
          <h3 class="font-sans text-xs font-semibold tracking-wide text-muted uppercase">
            Local service
          </h3>
          {!service.available
            ? (
              <EmptyState
                tone="warning"
                title="Service status unavailable"
                description={service.error ??
                  "systemd status requires Linux on the Sentinel host."}
                class="mt-3 !py-6"
              />
            )
            : (
              <dl class="mt-3 space-y-2 font-mono text-sm">
                <div class="flex justify-between gap-3 border-b border-border-subtle/70 pb-2">
                  <dt class="text-muted">Unit</dt>
                  <dd class="max-w-[65%] truncate text-end text-fg-strong">
                    {service.unit}
                  </dd>
                </div>
                <div class="flex justify-between gap-3 border-b border-border-subtle/70 pb-2">
                  <dt class="text-muted">Active</dt>
                  <dd class="text-fg-strong">
                    {service.activeState ?? "-"}
                    {service.subState ? ` / ${service.subState}` : ""}
                  </dd>
                </div>
                <div class="flex justify-between gap-3 border-b border-border-subtle/70 pb-2">
                  <dt class="text-muted">PID</dt>
                  <dd class="text-fg-strong">{service.mainPid ?? "-"}</dd>
                </div>
                <div class="flex justify-between gap-3">
                  <dt class="text-muted">Memory</dt>
                  <dd class="text-fg-strong">
                    {serviceMemoryLabel(service.memoryCurrentBytes)}
                  </dd>
                </div>
              </dl>
            )}
        </div>
      </div>
    </Panel>
  );
}

async function fetchRunners(): Promise<
  {
    ok: true;
    data: { runners: RunnerWithService[]; expectedCount: number };
  } | { ok: false; error: string }
> {
  try {
    const res = await fetch("/api/runners", {
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
    const body = await res.json() as {
      runners: RunnerWithService[];
      expectedCount: number;
    };
    return {
      ok: true,
      data: {
        runners: body.runners ?? [],
        expectedCount: body.expectedCount ?? 0,
      },
    };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Network error",
    };
  }
}

/** Live runner cards (+ optional detail) via WS / poll fallback. */
export default function RunnerGrid(props: RunnerGridProps) {
  const [runners, setRunners] = useState(props.initialRunners);
  const [expectedCount, setExpectedCount] = useState(props.expectedCount);
  const [error, setError] = useState(props.initialError);
  const [retrying, setRetrying] = useState(false);
  const { flashClass, liveMessage, markUpdated } = useRetryFeedback();
  const focusId = props.focusId ?? null;
  const showDetails = props.showDetails ?? false;

  useEffect(() => {
    return subscribeLiveFeed((snap) => {
      if (snap.errors?.runners && !snap.runners) {
        setError(snap.errors.runners);
        return;
      }
      if (snap.runners) {
        setRunners(snap.runners.runners);
        setExpectedCount(snap.runners.expectedCount);
        setError(null);
      }
    });
  }, []);

  const retry = async () => {
    setRetrying(true);
    const result = await fetchRunners();
    setRetrying(false);
    if (result.ok) {
      setRunners(result.data.runners);
      setExpectedCount(result.data.expectedCount);
      setError(null);
      markUpdated();
    } else {
      setError(result.error);
    }
  };

  const focused = focusId != null
    ? runners.find((r) => r.id === focusId) ?? null
    : null;
  const visible = focused ? [focused] : runners;

  if (error) {
    return (
      <EmptyState
        tone="error"
        title="Could not load runners"
        description={error}
        icon={<AlertTriangle class="size-4" aria-hidden="true" />}
        action={
          <Button
            type="button"
            variant="secondary"
            class="!py-1.5"
            disabled={retrying}
            onClick={retry}
          >
            {retrying ? "Retrying…" : "Retry"}
          </Button>
        }
      />
    );
  }

  if (runners.length === 0) {
    return (
      <EmptyState
        title="No runners registered"
        description={`No self-hosted runners found for ${props.org}. Confirm GITHUB_PAT has admin:org.`}
        icon={<Server class="size-4" aria-hidden="true" />}
        action={
          <Button
            type="button"
            variant="secondary"
            class="!py-1.5"
            disabled={retrying}
            onClick={retry}
          >
            {retrying ? "Retrying…" : "Retry"}
          </Button>
        }
      />
    );
  }

  return (
    <div class={`flex flex-col gap-5 ${flashClass}`.trim()}>
      <QuietLiveRegion message={liveMessage} />
      {showDetails && focused && (
        <p class="font-mono text-xs text-muted">
          Focusing <span class="text-fg-strong">{focused.name}</span>
          {" · "}
          <a href="/runners" class="text-accent-muted hover:underline">
            show all
          </a>
        </p>
      )}

      <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {visible.map((runner) => (
          <RunnerCard
            key={runner.id}
            runner={runner}
            highlighted={focusId === runner.id}
            href={showDetails
              ? (focused
                ? undefined
                : `/runners?id=${encodeURIComponent(String(runner.id))}`)
              : `/runners?id=${encodeURIComponent(String(runner.id))}`}
          />
        ))}
      </div>

      {showDetails &&
        visible.map((runner) => (
          <RunnerDetail key={`detail-${runner.id}`} runner={runner} />
        ))}

      {!showDetails && expectedCount > 0 && (
        <p class="sr-only">
          Expecting {expectedCount} runners
        </p>
      )}
    </div>
  );
}
