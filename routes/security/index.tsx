import { AlertTriangle, ExternalLink, Shield } from "lucide-preact";
import { Head } from "fresh/runtime";
import { page } from "fresh";
import { EmptyState } from "../../components/EmptyState.tsx";
import { Panel } from "../../components/Panel.tsx";
import { StatusBadge } from "../../components/StatusBadge.tsx";
import SecurityFeed from "../../islands/SecurityFeed.tsx";
import { caseStatusTone, severityTone } from "../../lib/format.ts";
import {
  isVigilConfigured,
  listAgents,
  listCases,
  listFindings,
  loadSecuritySnapshot,
  type VigilAgent,
  VigilApiError,
  type VigilCase,
  type VigilFinding,
  type VigilSecuritySnapshot,
  vigilUiBaseUrl,
} from "../../lib/vigil.ts";
import { define } from "../../utils.ts";

type SecurityPageData = {
  configured: boolean;
  uiUrl: string | undefined;
  snapshot: VigilSecuritySnapshot | null;
  findings: VigilFinding[];
  cases: VigilCase[];
  agents: VigilAgent[];
  currentAgent: string | null;
  error: string | null;
};

export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return ctx.redirect("/auth/login");
    }

    if (!isVigilConfigured()) {
      return page(
        {
          configured: false,
          uiUrl: undefined,
          snapshot: null,
          findings: [],
          cases: [],
          agents: [],
          currentAgent: null,
          error: null,
        } satisfies SecurityPageData,
      );
    }

    try {
      const [snapshot, findingsRes, casesRes, agentsRes] = await Promise.all([
        loadSecuritySnapshot(12),
        listFindings({ limit: 40 }),
        listCases(),
        listAgents(),
      ]);

      return page(
        {
          configured: true,
          uiUrl: vigilUiBaseUrl(),
          snapshot,
          findings: findingsRes.findings,
          cases: casesRes.cases,
          agents: agentsRes.agents,
          currentAgent: agentsRes.currentAgent,
          error: snapshot?.error ?? null,
        } satisfies SecurityPageData,
      );
    } catch (err) {
      const message = err instanceof VigilApiError
        ? err.message
        : err instanceof Error
        ? err.message
        : "Failed to load Vigil data";
      return page(
        {
          configured: true,
          uiUrl: vigilUiBaseUrl(),
          snapshot: null,
          findings: [],
          cases: [],
          agents: [],
          currentAgent: null,
          error: message,
        } satisfies SecurityPageData,
      );
    }
  },
});

export default define.page<typeof handler>(function SecurityPage({ data }) {
  const {
    configured,
    uiUrl,
    snapshot,
    findings,
    cases,
    agents,
    currentAgent,
    error,
  } = data;

  return (
    <>
      <Head>
        <title>Security · Sentinel</title>
      </Head>

      <div class="fade-rise flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 class="font-sans text-lg font-semibold tracking-tight text-fg-strong sm:text-xl">
            Security
          </h1>
          <p class="mt-0.5 text-sm text-muted">
            Vigil SOC findings, cases, and agents
          </p>
        </div>
        {uiUrl && (
          <a
            href={uiUrl}
            class="inline-flex items-center justify-center gap-2 rounded-md border border-border bg-surface-2/70 px-3.5 py-1.5 font-sans text-sm font-semibold text-fg transition-colors hover:border-accent-muted hover:bg-accent-soft"
            target="_blank"
            rel="noopener noreferrer"
          >
            Open Vigil
            <ExternalLink class="size-3.5" aria-hidden="true" />
          </a>
        )}
      </div>

      {!configured
        ? (
          <Panel class="fade-rise-delay">
            <EmptyState
              title="Vigil not configured"
              description="Set VIGIL_URL plus a Vigil service user (VIGIL_USERNAME / VIGIL_PASSWORD) to enable the security tab. The CI dashboard works without Vigil."
              icon={<Shield class="size-4" aria-hidden="true" />}
            />
          </Panel>
        )
        : (
          <>
            {error && !snapshot
              ? (
                <Panel class="fade-rise-delay">
                  <EmptyState
                    tone="error"
                    title="Vigil unavailable"
                    description={error}
                    icon={<AlertTriangle class="size-4" aria-hidden="true" />}
                  />
                </Panel>
              )
              : null}

            <div class="fade-rise-delay grid gap-3 sm:grid-cols-3">
              <Panel tone="subtle" title="Findings" class="!p-4">
                <p class="font-mono text-2xl font-semibold tabular-nums text-fg-strong">
                  {snapshot?.findingsTotal ?? findings.length}
                </p>
                <p class="mt-1 font-mono text-xs text-subtle">
                  {snapshot?.criticalCount ?? 0} critical ·{" "}
                  {snapshot?.highCount ?? 0} high
                </p>
              </Panel>
              <Panel tone="subtle" title="Cases" class="!p-4">
                <p class="font-mono text-2xl font-semibold tabular-nums text-fg-strong">
                  {snapshot?.activeCases ?? cases.length}
                </p>
                <p class="mt-1 font-mono text-xs text-subtle">
                  {snapshot?.casesTotal ?? cases.length} total
                </p>
              </Panel>
              <Panel tone="subtle" title="Agents" class="!p-4">
                <p class="font-mono text-2xl font-semibold tabular-nums text-fg-strong">
                  {snapshot?.agentsCount ?? agents.length}
                </p>
                <p class="mt-1 font-mono text-xs text-subtle">
                  {currentAgent
                    ? `current · ${currentAgent}`
                    : "from Vigil library"}
                </p>
              </Panel>
            </div>

            <Panel
              title="Recent findings"
              subtitle="Auto-refreshes via WebSocket when available"
              class="fade-rise-delay"
            >
              <SecurityFeed
                variant="panel"
                limit={12}
                initial={snapshot
                  ? {
                    enabled: true,
                    findingsTotal: snapshot.findingsTotal,
                    criticalCount: snapshot.criticalCount,
                    highCount: snapshot.highCount,
                    casesTotal: snapshot.casesTotal,
                    activeCases: snapshot.activeCases,
                    agentsCount: snapshot.agentsCount,
                    recentFindings: snapshot.recentFindings.length > 0
                      ? snapshot.recentFindings
                      : findings.slice(0, 12).map((f) => ({
                        findingId: f.findingId,
                        severity: f.severity,
                        status: f.status,
                        description: f.description,
                        timestamp: f.timestamp,
                        dataSource: f.dataSource,
                      })),
                    error: snapshot.error,
                  }
                  : null}
              />
            </Panel>

            <Panel
              title="Cases"
              subtitle="Active investigations from Vigil"
              class="fade-rise-delay"
            >
              {cases.length === 0
                ? (
                  <EmptyState
                    title="No cases"
                    description="Cases created in Vigil will show here."
                    icon={<Shield class="size-4" aria-hidden="true" />}
                  />
                )
                : (
                  <ul class="divide-y divide-border-subtle/70">
                    {cases.slice(0, 20).map((c) => (
                      <li
                        key={c.caseId}
                        class="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0 last:pb-0"
                      >
                        <div class="min-w-0 space-y-1">
                          <p class="font-sans text-sm font-medium text-fg-strong">
                            {c.title}
                          </p>
                          <p class="font-mono text-xs text-subtle">
                            {c.caseId}
                            {c.mitreTechniques.length > 0
                              ? ` · ${c.mitreTechniques.slice(0, 4).join(", ")}`
                              : ""}
                          </p>
                        </div>
                        <div class="flex flex-wrap gap-1.5">
                          <StatusBadge tone={severityTone(c.priority)}>
                            {c.priority}
                          </StatusBadge>
                          <StatusBadge tone={caseStatusTone(c.status)}>
                            {c.status}
                          </StatusBadge>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
            </Panel>

            <Panel
              title="Agents"
              subtitle="Vigil SOC agent library (not a live status feed)"
              class="fade-rise-delay"
            >
              {agents.length === 0
                ? (
                  <EmptyState
                    title="No agents listed"
                    description="Could not load agents from Vigil."
                    icon={<Shield class="size-4" aria-hidden="true" />}
                  />
                )
                : (
                  <ul class="grid gap-2 sm:grid-cols-2">
                    {agents.map((a) => (
                      <li
                        key={a.id}
                        class="rounded-lg border border-border-subtle/80 bg-surface-2/40 px-3 py-2.5"
                      >
                        <p class="font-sans text-sm font-medium text-fg-strong">
                          {a.name}
                          {currentAgent === a.id
                            ? (
                              <span class="ml-2 font-mono text-[0.65rem] uppercase text-accent-muted">
                                current
                              </span>
                            )
                            : null}
                        </p>
                        <p class="mt-0.5 font-mono text-xs text-subtle">
                          {a.id}
                          {a.specialization ? ` · ${a.specialization}` : ""}
                        </p>
                        {a.description
                          ? (
                            <p class="mt-1 line-clamp-2 text-sm text-muted">
                              {a.description}
                            </p>
                          )
                          : null}
                      </li>
                    ))}
                  </ul>
                )}
            </Panel>
          </>
        )}
    </>
  );
});
