/**
 * WebSocket / live-feed protocol helpers (pure: safe for islands + tests).
 *
 * Server pushes a `snapshot` about every 15s. Clients fall back to HTTP
 * polling of `/api/system`, `/api/runners`, `/api/runs` when WS is down.
 * No Live/Offline shell chrome: reconnect quietly.
 */
import type { OrgRunner, WorkflowRun } from "./github.ts";
import type { ServiceStatus, SystemMetricsPayload } from "./system.ts";

/** Mirrors dashboard RunnerWithService: kept local to avoid island bundling. */
export type RunnerWithService = OrgRunner & { service: ServiceStatus };

/** Server push cadence (and HTTP poll interval when WS is down). */
export const REALTIME_INTERVAL_MS = 15_000;

/** Give up waiting for WS open and fall back to poll. */
export const WS_CONNECT_TIMEOUT_MS = 5_000;

export const BACKOFF_BASE_MS = 1_000;
export const BACKOFF_MAX_MS = 30_000;
export const BACKOFF_JITTER_RATIO = 0.2;

/** Vigil SOC slice: null when VIGIL_URL unset; summary when configured. */
export type VigilFindingRealtime = {
  findingId: string;
  severity: string | null;
  status: string;
  description: string | null;
  timestamp: string | null;
  dataSource: string;
};

export type VigilRealtimeSlice = {
  enabled: boolean;
  findingsTotal?: number;
  criticalCount?: number;
  highCount?: number;
  casesTotal?: number;
  activeCases?: number;
  agentsCount?: number;
  recentFindings?: VigilFindingRealtime[];
  error?: string;
};

export type RunnersSnapshot = {
  expectedCount: number;
  totalCount: number;
  runners: RunnerWithService[];
};

export type RunsSnapshot = {
  totalCount: number;
  runs: WorkflowRun[];
};

export type SnapshotErrors = {
  system?: string;
  runners?: string;
  runs?: string;
};

export type SnapshotMessage = {
  type: "snapshot";
  ts: number;
  system: SystemMetricsPayload | null;
  runners: RunnersSnapshot | null;
  runs: RunsSnapshot | null;
  /** null when Vigil is not configured. */
  vigil: VigilRealtimeSlice | null;
  errors?: SnapshotErrors;
};

export type RealtimeMessage = SnapshotMessage;

/**
 * Exponential backoff with full jitter.
 * attempt 0 → ~base, then doubles up to max, ± ±jitterRatio.
 */
export function nextBackoffMs(
  attempt: number,
  opts?: {
    baseMs?: number;
    maxMs?: number;
    jitterRatio?: number;
    random?: () => number;
  },
): number {
  const base = opts?.baseMs ?? BACKOFF_BASE_MS;
  const max = opts?.maxMs ?? BACKOFF_MAX_MS;
  const jitterRatio = opts?.jitterRatio ?? BACKOFF_JITTER_RATIO;
  const random = opts?.random ?? Math.random;
  const exp = Math.min(max, base * Math.pow(2, Math.max(0, attempt)));
  const jitter = exp * jitterRatio * (random() * 2 - 1);
  return Math.max(0, Math.round(exp + jitter));
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asString(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}

function asNumber(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function parseVigilSlice(
  raw: Record<string, unknown>,
): VigilRealtimeSlice | null {
  if (typeof raw.enabled !== "boolean") return null;

  const recentRaw = Array.isArray(raw.recentFindings) ? raw.recentFindings : [];
  const recentFindings: VigilFindingRealtime[] = [];
  for (const item of recentRaw) {
    if (!isRecord(item)) continue;
    const findingId = asString(item.findingId);
    const status = asString(item.status);
    const dataSource = asString(item.dataSource);
    if (!findingId || !status || dataSource == null) continue;
    recentFindings.push({
      findingId,
      severity: asString(item.severity),
      status,
      description: asString(item.description),
      timestamp: asString(item.timestamp),
      dataSource,
    });
  }

  const slice: VigilRealtimeSlice = { enabled: raw.enabled };
  const findingsTotal = asNumber(raw.findingsTotal);
  const criticalCount = asNumber(raw.criticalCount);
  const highCount = asNumber(raw.highCount);
  const casesTotal = asNumber(raw.casesTotal);
  const activeCases = asNumber(raw.activeCases);
  const agentsCount = asNumber(raw.agentsCount);
  if (findingsTotal != null) slice.findingsTotal = findingsTotal;
  if (criticalCount != null) slice.criticalCount = criticalCount;
  if (highCount != null) slice.highCount = highCount;
  if (casesTotal != null) slice.casesTotal = casesTotal;
  if (activeCases != null) slice.activeCases = activeCases;
  if (agentsCount != null) slice.agentsCount = agentsCount;
  if (recentFindings.length > 0) slice.recentFindings = recentFindings;
  if (typeof raw.error === "string") slice.error = raw.error;
  return slice;
}

/** Parse a WS text frame into a protocol message, or null if invalid. */
export function parseWsMessage(raw: string): RealtimeMessage | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isRecord(data) || data.type !== "snapshot") return null;
  if (typeof data.ts !== "number" || !Number.isFinite(data.ts)) return null;

  const errors = isRecord(data.errors)
    ? {
      system: typeof data.errors.system === "string"
        ? data.errors.system
        : undefined,
      runners: typeof data.errors.runners === "string"
        ? data.errors.runners
        : undefined,
      runs: typeof data.errors.runs === "string" ? data.errors.runs : undefined,
    }
    : undefined;

  let vigil: VigilRealtimeSlice | null = null;
  if (data.vigil === null || data.vigil === undefined) {
    vigil = null;
  } else if (isRecord(data.vigil) && typeof data.vigil.enabled === "boolean") {
    vigil = parseVigilSlice(data.vigil);
    if (!vigil) return null;
  } else {
    return null;
  }

  return {
    type: "snapshot",
    ts: data.ts,
    system: (data.system ?? null) as SystemMetricsPayload | null,
    runners: (data.runners ?? null) as RunnersSnapshot | null,
    runs: (data.runs ?? null) as RunsSnapshot | null,
    vigil,
    errors,
  };
}

/** Build a WebSocket URL for the current page origin. */
export function realtimeWsUrl(
  loc: { protocol: string; host: string } = globalThis.location,
): string {
  const protocol = loc.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${loc.host}/api/ws`;
}
