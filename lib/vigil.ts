/**
 * Optional Vigil SOC API client.
 *
 * Callers must check `isVigilConfigured()` before use.
 * Auth: service user → POST /api/auth/login → Bearer JWT; refresh via
 * POST /api/auth/refresh. Endpoints: findings, cases, agents/agents
 * (no /api/agents/status). Payloads are normalized defensively for read-only UI.
 */
import { cache } from "./cache.ts";
import { optionalEnv } from "./env.ts";

const FINDINGS_TTL_MS = 30_000;
const CASES_TTL_MS = 30_000;
const FINDING_DETAIL_TTL_MS = 60_000;
const AGENTS_TTL_MS = 15_000;
/** Refresh a minute before typical 30m access-token expiry when exp is unknown. */
const DEFAULT_ACCESS_TTL_MS = 29 * 60 * 1000;
const REFRESH_SKEW_MS = 60_000;

export class VigilApiError extends Error {
  override name = "VigilApiError";
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

export type VigilFinding = {
  findingId: string;
  description: string | null;
  severity: string | null;
  status: string;
  dataSource: string;
  timestamp: string | null;
  anomalyScore: number | null;
  mitrePredictions: Record<string, number>;
  predictedTechniques: Array<{ techniqueId?: string; confidence?: number }>;
  entityContext: Record<string, unknown> | null;
  aiEnrichment: Record<string, unknown> | null;
  clusterId: string | null;
  externalId: string | null;
  createdAt: string | null;
  updatedAt: string | null;
};

export type VigilCase = {
  caseId: string;
  title: string;
  description: string | null;
  status: string;
  priority: string;
  assignee: string | null;
  tags: string[];
  mitreTechniques: string[];
  findingIds: string[];
  createdAt: string | null;
  updatedAt: string | null;
};

export type VigilAgent = {
  id: string;
  name: string;
  description: string;
  specialization: string;
  icon: string | null;
  color: string | null;
};

/** Compact finding row for WS / dashboard strip. */
export type VigilFindingSummary = {
  findingId: string;
  severity: string | null;
  status: string;
  description: string | null;
  timestamp: string | null;
  dataSource: string;
};

export type VigilSecuritySnapshot = {
  enabled: true;
  findingsTotal: number;
  criticalCount: number;
  highCount: number;
  casesTotal: number;
  activeCases: number;
  agentsCount: number;
  recentFindings: VigilFindingSummary[];
  error?: string;
};

type TokenState = {
  accessToken: string;
  refreshToken: string;
  /** Epoch ms when access token should be refreshed. */
  refreshAt: number;
};

let tokenState: TokenState | null = null;
let authInflight: Promise<TokenState> | null = null;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asString(v: unknown): string | null {
  return typeof v === "string" && v.length > 0 ? v : null;
}

function asNumber(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** True when VIGIL_URL is set (security UI may still fail if creds missing). */
export function isVigilConfigured(): boolean {
  return Boolean(optionalEnv("VIGIL_URL"));
}

/**
 * Heuristic Vigil web UI origin (backend :6987 → UI :6988).
 * No separate env var: matches common upstream docker compose ports.
 */
export function vigilUiBaseUrl(): string | undefined {
  const raw = optionalEnv("VIGIL_URL");
  if (!raw) return undefined;
  try {
    const u = new URL(raw);
    if (u.port === "6987") u.port = "6988";
    return u.origin;
  } catch {
    return undefined;
  }
}

function vigilBaseUrl(): string {
  const raw = optionalEnv("VIGIL_URL");
  if (!raw) {
    throw new VigilApiError("Vigil is not configured (VIGIL_URL unset)", 503);
  }
  return raw.replace(/\/+$/, "");
}

function vigilCredentials(): { username: string; password: string } {
  const username = optionalEnv("VIGIL_USERNAME");
  const password = optionalEnv("VIGIL_PASSWORD");
  if (!username || !password) {
    throw new VigilApiError(
      "Vigil credentials missing (VIGIL_USERNAME / VIGIL_PASSWORD)",
      503,
    );
  }
  return { username, password };
}

/** Decode JWT `exp` without verifying signature (expiry hint only). */
export function jwtExpiryMs(token: string): number | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, "="));
    const payload = JSON.parse(json) as { exp?: unknown };
    if (typeof payload.exp === "number" && Number.isFinite(payload.exp)) {
      return payload.exp * 1000;
    }
  } catch {
    // ignore
  }
  return null;
}

function tokenStateFromLogin(body: {
  access_token: string;
  refresh_token: string;
}): TokenState {
  const exp = jwtExpiryMs(body.access_token);
  const refreshAt = exp != null
    ? exp - REFRESH_SKEW_MS
    : Date.now() + DEFAULT_ACCESS_TTL_MS;
  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token,
    refreshAt,
  };
}

async function login(): Promise<TokenState> {
  const base = vigilBaseUrl();
  const { username, password } = vigilCredentials();
  const res = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      username_or_email: username,
      password,
    }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    throw new VigilApiError(
      `Vigil login failed (${res.status})${
        detail ? `: ${detail.slice(0, 200)}` : ""
      }`,
      res.status,
    );
  }
  const data = await res.json() as {
    access_token?: string;
    refresh_token?: string;
  };
  if (!data.access_token || !data.refresh_token) {
    throw new VigilApiError("Vigil login response missing tokens", 502);
  }
  tokenState = tokenStateFromLogin({
    access_token: data.access_token,
    refresh_token: data.refresh_token,
  });
  return tokenState;
}

async function refreshTokens(current: TokenState): Promise<TokenState> {
  const base = vigilBaseUrl();
  const res = await fetch(`${base}/api/auth/refresh`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ refresh_token: current.refreshToken }),
  });
  if (!res.ok) {
    // Force full re-login next
    tokenState = null;
    throw new VigilApiError(
      `Vigil token refresh failed (${res.status})`,
      res.status,
    );
  }
  const data = await res.json() as {
    access_token?: string;
    refresh_token?: string;
  };
  if (!data.access_token || !data.refresh_token) {
    tokenState = null;
    throw new VigilApiError("Vigil refresh response missing tokens", 502);
  }
  tokenState = tokenStateFromLogin({
    access_token: data.access_token,
    refresh_token: data.refresh_token,
  });
  return tokenState;
}

function ensureToken(forceLogin = false): Promise<TokenState> {
  if (!forceLogin && tokenState && Date.now() < tokenState.refreshAt) {
    return Promise.resolve(tokenState);
  }
  if (authInflight) return authInflight;

  authInflight = (async () => {
    try {
      if (!forceLogin && tokenState) {
        try {
          return await refreshTokens(tokenState);
        } catch {
          return await login();
        }
      }
      return await login();
    } finally {
      authInflight = null;
    }
  })();

  return authInflight;
}

async function vigilFetch(
  path: string,
  init?: RequestInit,
  retried = false,
): Promise<Response> {
  const base = vigilBaseUrl();
  const token = await ensureToken();
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  headers.set("Authorization", `Bearer ${token.accessToken}`);

  const res = await fetch(`${base}${path}`, { ...init, headers });
  if (res.status === 401 && !retried) {
    tokenState = null;
    await ensureToken(true);
    return vigilFetch(path, init, true);
  }
  return res;
}

function normalizeFinding(raw: unknown): VigilFinding | null {
  if (!isRecord(raw)) return null;
  const findingId = asString(raw.finding_id) ?? asString(raw.findingId);
  if (!findingId) return null;

  const mitreRaw = isRecord(raw.mitre_predictions)
    ? raw.mitre_predictions
    : isRecord(raw.mitrePredictions)
    ? raw.mitrePredictions
    : {};
  const mitrePredictions: Record<string, number> = {};
  for (const [k, v] of Object.entries(mitreRaw)) {
    if (typeof v === "number" && Number.isFinite(v)) mitrePredictions[k] = v;
  }

  const techniquesRaw = Array.isArray(raw.predicted_techniques)
    ? raw.predicted_techniques
    : Array.isArray(raw.predictedTechniques)
    ? raw.predictedTechniques
    : [];
  const predictedTechniques = techniquesRaw
    .filter(isRecord)
    .map((t) => ({
      techniqueId: asString(t.technique_id) ?? asString(t.techniqueId) ??
        undefined,
      confidence: asNumber(t.confidence) ?? undefined,
    }));

  return {
    findingId,
    description: asString(raw.description),
    severity: asString(raw.severity),
    status: asString(raw.status) ?? "unknown",
    dataSource: asString(raw.data_source) ?? asString(raw.dataSource) ??
      "unknown",
    timestamp: asString(raw.timestamp),
    anomalyScore: asNumber(raw.anomaly_score) ?? asNumber(raw.anomalyScore),
    mitrePredictions,
    predictedTechniques,
    entityContext: isRecord(raw.entity_context)
      ? raw.entity_context
      : isRecord(raw.entityContext)
      ? raw.entityContext
      : null,
    aiEnrichment: isRecord(raw.ai_enrichment)
      ? raw.ai_enrichment
      : isRecord(raw.aiEnrichment)
      ? raw.aiEnrichment
      : null,
    clusterId: asString(raw.cluster_id) ?? asString(raw.clusterId),
    externalId: asString(raw.external_id) ?? asString(raw.externalId),
    createdAt: asString(raw.created_at) ?? asString(raw.createdAt),
    updatedAt: asString(raw.updated_at) ?? asString(raw.updatedAt),
  };
}

function normalizeCase(raw: unknown): VigilCase | null {
  if (!isRecord(raw)) return null;
  const caseId = asString(raw.case_id) ?? asString(raw.caseId);
  if (!caseId) return null;
  const title = asString(raw.title) ?? caseId;
  const findingIdsRaw = Array.isArray(raw.finding_ids)
    ? raw.finding_ids
    : Array.isArray(raw.findingIds)
    ? raw.findingIds
    : [];
  const tagsRaw = Array.isArray(raw.tags) ? raw.tags : [];
  const mitreRaw = Array.isArray(raw.mitre_techniques)
    ? raw.mitre_techniques
    : Array.isArray(raw.mitreTechniques)
    ? raw.mitreTechniques
    : [];

  return {
    caseId,
    title,
    description: asString(raw.description),
    status: asString(raw.status) ?? "unknown",
    priority: asString(raw.priority) ?? "medium",
    assignee: asString(raw.assignee),
    tags: tagsRaw.filter((t): t is string => typeof t === "string"),
    mitreTechniques: mitreRaw.filter((t): t is string => typeof t === "string"),
    findingIds: findingIdsRaw.filter((t): t is string => typeof t === "string"),
    createdAt: asString(raw.created_at) ?? asString(raw.createdAt),
    updatedAt: asString(raw.updated_at) ?? asString(raw.updatedAt),
  };
}

function normalizeAgent(raw: unknown): VigilAgent | null {
  if (!isRecord(raw)) return null;
  const id = asString(raw.id);
  const name = asString(raw.name);
  if (!id || !name) return null;
  return {
    id,
    name,
    description: asString(raw.description) ?? "",
    specialization: asString(raw.specialization) ?? "",
    icon: asString(raw.icon),
    color: asString(raw.color),
  };
}

function toFindingSummary(f: VigilFinding): VigilFindingSummary {
  return {
    findingId: f.findingId,
    severity: f.severity,
    status: f.status,
    description: f.description,
    timestamp: f.timestamp,
    dataSource: f.dataSource,
  };
}

export type ListFindingsOpts = {
  limit?: number;
  offset?: number;
  severity?: string;
  status?: string;
};

export async function listFindings(
  opts: ListFindingsOpts = {},
): Promise<{ findings: VigilFinding[]; total: number }> {
  const limit = opts.limit ?? 50;
  const offset = opts.offset ?? 0;
  const cacheKey = `vigil:findings:${limit}:${offset}:${opts.severity ?? ""}:${
    opts.status ?? ""
  }`;
  const cached = cache.get<{ findings: VigilFinding[]; total: number }>(
    cacheKey,
  );
  if (cached) return cached;

  const params = new URLSearchParams();
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  if (opts.severity) params.set("severity", opts.severity);
  if (opts.status) params.set("status", opts.status);

  const res = await vigilFetch(`/api/findings?${params}`);
  if (!res.ok) {
    throw new VigilApiError(
      `Vigil findings failed (${res.status})`,
      res.status,
    );
  }
  const data = await res.json() as {
    findings?: unknown[];
    total?: number;
  };
  const findings = (data.findings ?? [])
    .map(normalizeFinding)
    .filter((f): f is VigilFinding => f != null);
  const total = typeof data.total === "number" ? data.total : findings.length;
  const result = { findings, total };
  cache.set(cacheKey, result, FINDINGS_TTL_MS);
  return result;
}

export async function getFinding(findingId: string): Promise<VigilFinding> {
  const id = findingId.trim();
  if (!id || id.length > 80 || !/^[\w.-]+$/.test(id)) {
    throw new VigilApiError("Invalid finding id", 400);
  }
  const cacheKey = `vigil:finding:${id}`;
  const cached = cache.get<VigilFinding>(cacheKey);
  if (cached) return cached;

  const res = await vigilFetch(`/api/findings/${encodeURIComponent(id)}`);
  if (res.status === 404) {
    throw new VigilApiError("Finding not found", 404);
  }
  if (!res.ok) {
    throw new VigilApiError(
      `Vigil finding detail failed (${res.status})`,
      res.status,
    );
  }
  const finding = normalizeFinding(await res.json());
  if (!finding) {
    throw new VigilApiError("Invalid finding payload", 502);
  }
  cache.set(cacheKey, finding, FINDING_DETAIL_TTL_MS);
  return finding;
}

export async function listCases(opts?: {
  status?: string;
  priority?: string;
}): Promise<{ cases: VigilCase[]; total: number }> {
  const cacheKey = `vigil:cases:${opts?.status ?? ""}:${opts?.priority ?? ""}`;
  const cached = cache.get<{ cases: VigilCase[]; total: number }>(cacheKey);
  if (cached) return cached;

  const params = new URLSearchParams();
  if (opts?.status) params.set("status", opts.status);
  if (opts?.priority) params.set("priority", opts.priority);
  const qs = params.toString();
  const res = await vigilFetch(`/api/cases${qs ? `?${qs}` : ""}`);
  if (!res.ok) {
    throw new VigilApiError(`Vigil cases failed (${res.status})`, res.status);
  }
  const data = await res.json() as { cases?: unknown[]; total?: number };
  const cases = (data.cases ?? [])
    .map(normalizeCase)
    .filter((c): c is VigilCase => c != null);
  const total = typeof data.total === "number" ? data.total : cases.length;
  const result = { cases, total };
  cache.set(cacheKey, result, CASES_TTL_MS);
  return result;
}

export async function listAgents(): Promise<{
  agents: VigilAgent[];
  currentAgent: string | null;
}> {
  const cacheKey = "vigil:agents";
  const cached = cache.get<
    { agents: VigilAgent[]; currentAgent: string | null }
  >(
    cacheKey,
  );
  if (cached) return cached;

  const res = await vigilFetch("/api/agents/agents");
  if (!res.ok) {
    throw new VigilApiError(`Vigil agents failed (${res.status})`, res.status);
  }
  const data = await res.json() as {
    agents?: unknown[];
    current_agent?: string;
  };
  const agents = (data.agents ?? [])
    .map(normalizeAgent)
    .filter((a): a is VigilAgent => a != null);
  const result = {
    agents,
    currentAgent: asString(data.current_agent),
  };
  cache.set(cacheKey, result, AGENTS_TTL_MS);
  return result;
}

/**
 * Aggregated security snapshot for dashboard strip + WebSocket.
 * Soft-fails into `{ enabled: true, error, …empty counts }` when Vigil is up
 * but a call fails: never throws when configured.
 */
export async function loadSecuritySnapshot(
  recentLimit = 8,
): Promise<VigilSecuritySnapshot | null> {
  if (!isVigilConfigured()) return null;

  try {
    const [findingsRes, casesRes, agentsRes] = await Promise.all([
      listFindings({ limit: Math.max(recentLimit, 50) }),
      listCases(),
      listAgents(),
    ]);

    let criticalCount = 0;
    let highCount = 0;
    for (const f of findingsRes.findings) {
      const s = (f.severity ?? "").toLowerCase();
      if (s === "critical") criticalCount += 1;
      else if (s === "high") highCount += 1;
    }

    const activeCases = casesRes.cases.filter((c) => {
      const s = c.status.toLowerCase();
      return s !== "closed" && s !== "resolved" && s !== "archived";
    }).length;

    return {
      enabled: true,
      findingsTotal: findingsRes.total,
      criticalCount,
      highCount,
      casesTotal: casesRes.total,
      activeCases,
      agentsCount: agentsRes.agents.length,
      recentFindings: findingsRes.findings
        .slice(0, recentLimit)
        .map(toFindingSummary),
    };
  } catch (err) {
    const message = err instanceof VigilApiError
      ? err.message
      : err instanceof Error
      ? err.message
      : "Failed to load Vigil data";
    return {
      enabled: true,
      findingsTotal: 0,
      criticalCount: 0,
      highCount: 0,
      casesTotal: 0,
      activeCases: 0,
      agentsCount: 0,
      recentFindings: [],
      error: message,
    };
  }
}

/** Test helper: clear cached JWT + response TTL entries. */
export function resetVigilAuthForTests(): void {
  tokenState = null;
  authInflight = null;
}
