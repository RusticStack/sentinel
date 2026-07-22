import { useEffect, useState } from "preact/hooks";
import { AlertTriangle, Shield } from "lucide-preact";
import { FindingCard } from "../components/FindingCard.tsx";
import { EmptyState } from "../components/EmptyState.tsx";
import { StatusBadge } from "../components/StatusBadge.tsx";
import { Button } from "../components/Button.tsx";
import { subscribeLiveFeed } from "../lib/live_feed.ts";
import { QuietLiveRegion, useRetryFeedback } from "../lib/quiet_refresh.tsx";
import type { VigilRealtimeSlice } from "../lib/realtime.ts";
import { REALTIME_INTERVAL_MS } from "../lib/realtime.ts";

export type SecurityFeedInitial = {
  enabled: true;
  findingsTotal: number;
  criticalCount: number;
  highCount: number;
  casesTotal: number;
  activeCases: number;
  agentsCount: number;
  recentFindings: Array<{
    findingId: string;
    severity: string | null;
    status: string;
    description: string | null;
    timestamp: string | null;
    dataSource: string;
  }>;
  error?: string;
};

export type SecurityFeedProps = {
  initial: SecurityFeedInitial | null;
  /** Dashboard strip vs full security page list. */
  variant?: "strip" | "panel";
  /** Max findings shown. */
  limit?: number;
};

function isSecurityPayload(v: unknown): v is SecurityFeedInitial {
  return typeof v === "object" && v !== null &&
    (v as { enabled?: unknown }).enabled === true;
}

async function fetchSecurity(): Promise<
  { ok: true; data: SecurityFeedInitial | null } | {
    ok: false;
    error: string;
  }
> {
  try {
    const res = await fetch("/api/security", {
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
    const body = await res.json();
    if (body?.enabled === false) return { ok: true, data: null };
    if (isSecurityPayload(body)) return { ok: true, data: body };
    return { ok: false, error: "Unexpected security payload" };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Network error",
    };
  }
}

/** Auto-refreshing Vigil findings (WS first, `/api/security` poll fallback). */
export default function SecurityFeed(props: SecurityFeedProps) {
  const variant = props.variant ?? "panel";
  const limit = props.limit ?? (variant === "strip" ? 5 : 12);
  const [snap, setSnap] = useState<SecurityFeedInitial | null>(props.initial);
  const [error, setError] = useState<string | null>(
    props.initial?.error ?? null,
  );
  const [retrying, setRetrying] = useState(false);
  const { flashClass, liveMessage, markUpdated } = useRetryFeedback();

  useEffect(() => {
    let cancelled = false;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const applyVigil = (vigil: VigilRealtimeSlice | null) => {
      if (!vigil || !vigil.enabled) return;
      setSnap({
        enabled: true,
        findingsTotal: vigil.findingsTotal ?? 0,
        criticalCount: vigil.criticalCount ?? 0,
        highCount: vigil.highCount ?? 0,
        casesTotal: vigil.casesTotal ?? 0,
        activeCases: vigil.activeCases ?? 0,
        agentsCount: vigil.agentsCount ?? 0,
        recentFindings: vigil.recentFindings ?? [],
        error: vigil.error,
      });
      setError(vigil.error ?? null);
    };

    const unsub = subscribeLiveFeed((msg) => {
      if (msg.vigil) applyVigil(msg.vigil);
    });

    const poll = async () => {
      try {
        const res = await fetch("/api/security", {
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        if (!res.ok || cancelled) return;
        const body = await res.json();
        if (cancelled) return;
        if (body?.enabled === false) {
          setSnap(null);
          return;
        }
        if (isSecurityPayload(body)) {
          setSnap(body);
          setError(body.error ?? null);
        }
      } catch {
        // quiet: SSR initial remains
      }
    };

    // Poll as progressive enhancement when WS does not carry vigil yet
    void poll();
    pollTimer = setInterval(() => {
      void poll();
    }, REALTIME_INTERVAL_MS);

    return () => {
      cancelled = true;
      unsub();
      if (pollTimer != null) clearInterval(pollTimer);
    };
  }, []);

  const retry = async () => {
    setRetrying(true);
    const result = await fetchSecurity();
    setRetrying(false);
    if (result.ok) {
      setSnap(result.data);
      setError(result.data?.error ?? null);
      markUpdated();
    } else {
      setError(result.error);
    }
  };

  if (!snap) {
    return null;
  }

  const findings = snap.recentFindings.slice(0, limit);
  const retryBtn = (
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

  if (variant === "strip") {
    return (
      <div class={`space-y-3 ${flashClass}`.trim()}>
        <QuietLiveRegion message={liveMessage} />
        <div class="flex flex-wrap items-center gap-2">
          <StatusBadge tone="info">{snap.findingsTotal} findings</StatusBadge>
          {snap.criticalCount > 0 && (
            <StatusBadge tone="error">
              {snap.criticalCount} critical
            </StatusBadge>
          )}
          {snap.highCount > 0 && (
            <StatusBadge tone="warning">{snap.highCount} high</StatusBadge>
          )}
          <StatusBadge tone="busy">{snap.activeCases} open cases</StatusBadge>
        </div>
        {error
          ? (
            <EmptyState
              tone="warning"
              title="Vigil unavailable"
              description={error}
              icon={<AlertTriangle class="size-4" aria-hidden="true" />}
              action={retryBtn}
            />
          )
          : findings.length === 0
          ? (
            <EmptyState
              title="No recent findings"
              description="Vigil has not reported findings yet."
              icon={<Shield class="size-4" aria-hidden="true" />}
              action={retryBtn}
            />
          )
          : (
            <ul class="space-y-2">
              {findings.map((f) => (
                <li key={f.findingId}>
                  <FindingCard
                    compact
                    findingId={f.findingId}
                    severity={f.severity}
                    status={f.status}
                    description={f.description}
                    timestamp={f.timestamp}
                    dataSource={f.dataSource}
                  />
                </li>
              ))}
            </ul>
          )}
        <Button href="/security" variant="secondary" class="!py-1.5">
          Security overview
        </Button>
      </div>
    );
  }

  return (
    <div class={`space-y-3 ${flashClass}`.trim()}>
      <QuietLiveRegion message={liveMessage} />
      {error
        ? (
          <EmptyState
            tone="warning"
            title="Could not refresh Vigil"
            description={error}
            icon={<AlertTriangle class="size-4" aria-hidden="true" />}
            action={retryBtn}
          />
        )
        : null}
      {findings.length === 0 && !error
        ? (
          <EmptyState
            title="No findings yet"
            description="Findings from Vigil will appear here as they are ingested."
            icon={<Shield class="size-4" aria-hidden="true" />}
            action={retryBtn}
          />
        )
        : (
          <ul class="space-y-2">
            {findings.map((f) => (
              <li key={f.findingId}>
                <FindingCard
                  findingId={f.findingId}
                  severity={f.severity}
                  status={f.status}
                  description={f.description}
                  timestamp={f.timestamp}
                  dataSource={f.dataSource}
                />
              </li>
            ))}
          </ul>
        )}
    </div>
  );
}
