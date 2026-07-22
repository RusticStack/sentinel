import { AlertTriangle, ArrowLeft, ExternalLink, Shield } from "lucide-preact";
import { Head } from "fresh/runtime";
import { page } from "fresh";
import { Button } from "../../../components/Button.tsx";
import { EmptyState } from "../../../components/EmptyState.tsx";
import { Panel } from "../../../components/Panel.tsx";
import { StatusBadge } from "../../../components/StatusBadge.tsx";
import { formatRelativeTime, severityTone } from "../../../lib/format.ts";
import {
  getFinding,
  isVigilConfigured,
  VigilApiError,
  type VigilFinding,
  vigilUiBaseUrl,
} from "../../../lib/vigil.ts";
import { define } from "../../../utils.ts";

type FindingPageData = {
  configured: boolean;
  finding: VigilFinding | null;
  error: string | null;
  notFound: boolean;
  uiUrl: string | undefined;
};

export const handler = define.handlers({
  async GET(ctx) {
    if (!ctx.state.user) {
      return ctx.redirect("/auth/login");
    }

    const id = ctx.params.id?.trim() ?? "";

    if (!isVigilConfigured()) {
      return page(
        {
          configured: false,
          finding: null,
          error: null,
          notFound: false,
          uiUrl: undefined,
        } satisfies FindingPageData,
      );
    }

    if (!id) {
      return page(
        {
          configured: true,
          finding: null,
          error: "Missing finding id",
          notFound: true,
          uiUrl: vigilUiBaseUrl(),
        } satisfies FindingPageData,
      );
    }

    try {
      const finding = await getFinding(id);
      return page(
        {
          configured: true,
          finding,
          error: null,
          notFound: false,
          uiUrl: vigilUiBaseUrl(),
        } satisfies FindingPageData,
      );
    } catch (err) {
      const notFound = err instanceof VigilApiError && err.status === 404;
      const message = err instanceof VigilApiError
        ? err.message
        : err instanceof Error
        ? err.message
        : "Failed to load finding";
      return page(
        {
          configured: true,
          finding: null,
          error: message,
          notFound,
          uiUrl: vigilUiBaseUrl(),
        } satisfies FindingPageData,
      );
    }
  },
});

export default define.page<typeof handler>(function FindingDetailPage(
  { data },
) {
  const { configured, finding, error, notFound, uiUrl } = data;
  const mitreEntries = finding
    ? Object.entries(finding.mitrePredictions).sort((a, b) => b[1] - a[1])
    : [];

  return (
    <>
      <Head>
        <title>
          {finding
            ? `${finding.findingId} · Security · Sentinel`
            : "Finding · Security · Sentinel"}
        </title>
      </Head>

      <div class="fade-rise">
        <Button href="/security" variant="ghost" class="!px-2 !py-1 text-xs">
          <ArrowLeft class="size-3.5" aria-hidden="true" />
          Back to security
        </Button>
      </div>

      {!configured
        ? (
          <Panel class="fade-rise-delay">
            <EmptyState
              title="Vigil not configured"
              description="Finding detail requires VIGIL_URL and a Vigil service user."
              icon={<Shield class="size-4" aria-hidden="true" />}
            />
          </Panel>
        )
        : notFound || !finding
        ? (
          <Panel class="fade-rise-delay">
            <EmptyState
              tone={notFound ? "neutral" : "error"}
              title={notFound ? "Finding not found" : "Could not load finding"}
              description={error ?? "Unknown error"}
              icon={<AlertTriangle class="size-4" aria-hidden="true" />}
              action={
                <Button href="/security" variant="secondary">
                  Security overview
                </Button>
              }
            />
          </Panel>
        )
        : (
          <>
            <div class="fade-rise-delay flex flex-wrap items-end justify-between gap-3">
              <div>
                <h1 class="font-mono text-lg font-semibold tracking-tight text-fg-strong sm:text-xl">
                  {finding.findingId}
                </h1>
                <p class="mt-0.5 text-sm text-muted">
                  {finding.dataSource}
                  {finding.timestamp
                    ? ` · ${formatRelativeTime(finding.timestamp)}`
                    : ""}
                </p>
              </div>
              <div class="flex flex-wrap items-center gap-2">
                <StatusBadge tone={severityTone(finding.severity)}>
                  {finding.severity ?? "unknown"}
                </StatusBadge>
                <StatusBadge tone="info">{finding.status}</StatusBadge>
                {uiUrl && (
                  <a
                    href={`${uiUrl}/findings/${
                      encodeURIComponent(finding.findingId)
                    }`}
                    class="inline-flex items-center justify-center gap-2 rounded-md border border-border bg-surface-2/70 px-3.5 py-1.5 font-sans text-sm font-semibold text-fg transition-colors hover:border-accent-muted hover:bg-accent-soft"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Open in Vigil
                    <ExternalLink class="size-3.5" aria-hidden="true" />
                  </a>
                )}
              </div>
            </div>

            <Panel title="Description" class="fade-rise-delay">
              <p class="text-sm leading-relaxed text-fg">
                {finding.description?.trim() || "No description provided."}
              </p>
              {finding.anomalyScore != null && (
                <p class="mt-3 font-mono text-xs text-subtle">
                  Anomaly score · {finding.anomalyScore.toFixed(2)}
                </p>
              )}
            </Panel>

            {mitreEntries.length > 0 && (
              <Panel
                title="MITRE ATT&CK"
                subtitle="Predicted techniques"
                class="fade-rise-delay"
              >
                <ul class="space-y-2">
                  {mitreEntries.slice(0, 12).map(([id, conf]) => (
                    <li
                      key={id}
                      class="flex items-center justify-between gap-3 rounded-lg border border-border-subtle/70 px-3 py-2"
                    >
                      <span class="font-mono text-sm text-fg-strong">{id}</span>
                      <span class="font-mono text-xs text-subtle">
                        {(conf * 100).toFixed(0)}%
                      </span>
                    </li>
                  ))}
                </ul>
              </Panel>
            )}

            {finding.entityContext &&
              Object.keys(finding.entityContext).length > 0 && (
              <Panel title="Entity context" class="fade-rise-delay">
                <pre class="overflow-x-auto rounded-lg bg-surface-3/60 p-3 font-mono text-xs text-fg">
                  {JSON.stringify(finding.entityContext, null, 2)}
                </pre>
              </Panel>
            )}

            {finding.aiEnrichment && (
              <Panel title="AI enrichment" class="fade-rise-delay">
                <pre class="overflow-x-auto rounded-lg bg-surface-3/60 p-3 font-mono text-xs text-fg">
                  {JSON.stringify(finding.aiEnrichment, null, 2)}
                </pre>
              </Panel>
            )}
          </>
        )}
    </>
  );
});
