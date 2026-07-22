/**
 * Browser live-feed: prefer WebSocket `/api/ws`, fall back to HTTP poll.
 * Ref-counted so remounts do not stack duplicate intervals/sockets.
 */
import type { WorkflowRun } from "./github.ts";
import type { SystemMetricsPayload } from "./system.ts";
import {
  nextBackoffMs,
  parseWsMessage,
  REALTIME_INTERVAL_MS,
  realtimeWsUrl,
  type RunnerWithService,
  type SnapshotMessage,
  type VigilRealtimeSlice,
  WS_CONNECT_TIMEOUT_MS,
} from "./realtime.ts";

export type LiveFeedListener = (snapshot: SnapshotMessage) => void;

const listeners = new Set<LiveFeedListener>();

let refCount = 0;
let stopped = true;
let attempt = 0;
let socket: WebSocket | null = null;
let pollTimer: ReturnType<typeof setInterval> | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let connectTimer: ReturnType<typeof setTimeout> | null = null;

function emit(snapshot: SnapshotMessage): void {
  for (const listener of listeners) {
    try {
      listener(snapshot);
    } catch {
      // Listener errors must not tear down the feed.
    }
  }
}

function clearConnectTimer(): void {
  if (connectTimer != null) {
    clearTimeout(connectTimer);
    connectTimer = null;
  }
}

function clearReconnectTimer(): void {
  if (reconnectTimer != null) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

function stopPolling(): void {
  if (pollTimer != null) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function detachSocket(): void {
  clearConnectTimer();
  if (!socket) return;
  const ws = socket;
  socket = null;
  ws.onopen = null;
  ws.onmessage = null;
  ws.onerror = null;
  ws.onclose = null;
  try {
    ws.close();
  } catch {
    // ignore
  }
}

async function fetchJson<T>(url: string): Promise<
  { ok: true; data: T } | {
    ok: false;
    error: string;
  }
> {
  try {
    const res = await fetch(url, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      let message = `HTTP ${res.status}`;
      try {
        const body = await res.json() as { error?: string };
        if (body?.error) message = body.error;
      } catch {
        // ignore body parse
      }
      return { ok: false, error: message };
    }
    return { ok: true, data: await res.json() as T };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Network error",
    };
  }
}

async function pollOnce(): Promise<void> {
  if (stopped) return;

  const [systemRes, runnersRes, runsRes, securityRes] = await Promise.all([
    fetchJson<SystemMetricsPayload>("/api/system"),
    fetchJson<{
      expectedCount: number;
      totalCount: number;
      runners: RunnerWithService[];
    }>("/api/runners"),
    fetchJson<{ totalCount: number; runs: WorkflowRun[] }>(
      "/api/runs?limit=50",
    ),
    fetchJson<VigilRealtimeSlice | { enabled: false }>("/api/security"),
  ]);

  if (stopped) return;

  const errors: SnapshotMessage["errors"] = {};
  if (!systemRes.ok) errors.system = systemRes.error;
  if (!runnersRes.ok) errors.runners = runnersRes.error;
  if (!runsRes.ok) errors.runs = runsRes.error;

  let vigil: VigilRealtimeSlice | null = null;
  if (
    securityRes.ok && securityRes.data &&
    "enabled" in securityRes.data && securityRes.data.enabled === true
  ) {
    vigil = securityRes.data as VigilRealtimeSlice;
  }

  emit({
    type: "snapshot",
    ts: Date.now(),
    system: systemRes.ok ? systemRes.data : null,
    runners: runnersRes.ok ? runnersRes.data : null,
    runs: runsRes.ok ? runsRes.data : null,
    vigil,
    errors: Object.keys(errors).length > 0 ? errors : undefined,
  });
}

function startPolling(): void {
  if (pollTimer != null || stopped) return;
  void pollOnce();
  pollTimer = setInterval(() => {
    void pollOnce();
  }, REALTIME_INTERVAL_MS);
}

function scheduleReconnect(): void {
  if (stopped || reconnectTimer != null) return;
  const delay = nextBackoffMs(attempt);
  attempt += 1;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectWs();
  }, delay);
}

function onSocketLost(): void {
  clearConnectTimer();
  socket = null;
  startPolling();
  scheduleReconnect();
}

function connectWs(): void {
  if (stopped) return;
  detachSocket();

  let ws: WebSocket;
  try {
    ws = new WebSocket(realtimeWsUrl());
  } catch {
    onSocketLost();
    return;
  }

  socket = ws;

  connectTimer = setTimeout(() => {
    connectTimer = null;
    if (socket === ws && ws.readyState !== WebSocket.OPEN) {
      try {
        ws.close();
      } catch {
        // ignore
      }
      // onclose may not fire if never opened: force fallback
      if (socket === ws) {
        detachSocket();
        onSocketLost();
      }
    }
  }, WS_CONNECT_TIMEOUT_MS);

  ws.onopen = () => {
    clearConnectTimer();
    attempt = 0;
    clearReconnectTimer();
    stopPolling();
  };

  ws.onmessage = (event) => {
    if (typeof event.data !== "string") return;
    const msg = parseWsMessage(event.data);
    if (msg) emit(msg);
  };

  ws.onerror = () => {
    // close follows; avoid double-scheduling here
  };

  ws.onclose = () => {
    if (socket !== ws) return;
    socket = null;
    onSocketLost();
  };
}

function startFeed(): void {
  if (!stopped) return;
  stopped = false;
  attempt = 0;
  connectWs();
}

function stopFeed(): void {
  stopped = true;
  clearReconnectTimer();
  clearConnectTimer();
  stopPolling();
  detachSocket();
  attempt = 0;
}

/**
 * Subscribe to live dashboard snapshots.
 * First subscriber starts WS (with poll fallback); last unsubscriber tears down.
 */
export function subscribeLiveFeed(listener: LiveFeedListener): () => void {
  listeners.add(listener);
  refCount += 1;
  if (refCount === 1) startFeed();

  return () => {
    listeners.delete(listener);
    refCount = Math.max(0, refCount - 1);
    if (refCount === 0) stopFeed();
  };
}

/** Test helper: reset singleton state between unit tests. */
export function resetLiveFeedForTests(): void {
  stopFeed();
  listeners.clear();
  refCount = 0;
}
