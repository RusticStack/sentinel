import { useEffect, useState } from "preact/hooks";
import { AlertTriangle, Gauge } from "lucide-preact";
import { Button } from "../components/Button.tsx";
import { EmptyState } from "../components/EmptyState.tsx";
import { StatMeter } from "../components/StatMeter.tsx";
import { subscribeLiveFeed } from "../lib/live_feed.ts";
import { QuietLiveRegion, useRetryFeedback } from "../lib/quiet_refresh.tsx";
import { formatMemoryMb, memoryUsedPercent } from "../lib/format.ts";
import { seriesValues } from "../lib/metric_series.ts";
import type { SystemMetricsPayload } from "../lib/system.ts";

export type SystemStatsProps = {
  initialSystem: SystemMetricsPayload | null;
  initialError: string | null;
};

async function fetchSystem(): Promise<
  { ok: true; data: SystemMetricsPayload } | { ok: false; error: string }
> {
  try {
    const res = await fetch("/api/system", {
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
    return { ok: true, data: await res.json() as SystemMetricsPayload };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Network error",
    };
  }
}

/** Auto-refreshing host metrics (SSR first, then WS / poll). */
export default function SystemStats(props: SystemStatsProps) {
  const [system, setSystem] = useState(props.initialSystem);
  const [error, setError] = useState(props.initialError);
  const [retrying, setRetrying] = useState(false);
  const { flashClass, liveMessage, markUpdated } = useRetryFeedback();

  useEffect(() => {
    return subscribeLiveFeed((snap) => {
      if (snap.errors?.system && !snap.system) {
        setError(snap.errors.system);
        return;
      }
      if (snap.system) {
        setSystem(snap.system);
        setError(null);
      }
    });
  }, []);

  const retry = async () => {
    setRetrying(true);
    const result = await fetchSystem();
    setRetrying(false);
    if (result.ok) {
      setSystem(result.data);
      setError(null);
      markUpdated();
    } else {
      setError(result.error);
    }
  };

  const memPct = system?.memory
    ? memoryUsedPercent(system.memory.usedMb, system.memory.totalMb)
    : null;

  const history = system?.history;
  const memSeries = history ? seriesValues(history, "memPct") : [];
  const diskSeries = history ? seriesValues(history, "diskPct") : [];
  const loadSeries = history ? seriesValues(history, "load1") : [];

  if (error) {
    return (
      <EmptyState
        tone="error"
        title="System metrics failed"
        description={error}
        icon={<Gauge class="size-4" aria-hidden="true" />}
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

  if (system && !system.available) {
    return (
      <EmptyState
        tone="warning"
        title="Host metrics unavailable"
        description={system.error ??
          "System stats require a Linux host (graceful degrade here)."}
        icon={<Gauge class="size-4" aria-hidden="true" />}
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

  if (!system) {
    return (
      <EmptyState
        title="No system data"
        description="Metrics have not loaded yet."
        icon={<AlertTriangle class="size-4" aria-hidden="true" />}
        action={
          <Button
            type="button"
            variant="secondary"
            class="!py-1.5"
            disabled={retrying}
            onClick={retry}
          >
            {retrying ? "Loading…" : "Load metrics"}
          </Button>
        }
      />
    );
  }

  return (
    <div class={`meters-stack ${flashClass}`.trim()}>
      <QuietLiveRegion message={liveMessage} />
      {system.memory && (
        <StatMeter
          label="Memory"
          value={formatMemoryMb(
            system.memory.usedMb,
            system.memory.totalMb,
          )}
          percent={memPct}
          series={memSeries}
        />
      )}
      {system.disk && (
        <StatMeter
          label="Disk"
          value={`${system.disk.used} / ${system.disk.size}`}
          percent={system.disk.usePercent}
          hint={system.disk.mount}
          series={diskSeries}
        />
      )}
      {system.load && (
        <StatMeter
          label="Load"
          value={`${system.load.load1.toFixed(2)} · ${
            system.load.load5.toFixed(2)
          } · ${system.load.load15.toFixed(2)}`}
          hint={system.uptime ?? undefined}
          series={loadSeries}
        />
      )}
      {!system.memory && !system.disk && !system.load && (
        <p class="text-sm text-muted">No metrics collected.</p>
      )}
    </div>
  );
}
