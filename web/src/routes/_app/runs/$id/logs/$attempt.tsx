// The log viewer: data read on the server (ssr: 'data-only'), the windowed DOM built in the browser by the unchanged
// logviewer.ts, which keeps its quarter-million lines outside React's state.
import { useEffect, useRef, useState } from "react";
import { createFileRoute, notFound, useNavigate } from "@tanstack/react-router";
import type { Explanation, LogPage, Run, StepRecord, Steps } from "../../../../../lib/types";
import { api, ApiError } from "../../../../../lib/api.ts";
import { LogViewer } from "../../../../../lib/logviewer.ts";
import { announce } from "../../../../../lib/announce.tsx";
import { refreshTenants } from "../../../../../lib/session.ts";
import { fmtNs, shortId, words } from "../../../../../lib/format.ts";
import { NO_CONTROL, searchSchema } from "../../../../../lib/search.ts";
import { Page } from "../../../../../components/Page.tsx";
import { StateBadge } from "../../../../../components/StateBadge.tsx";
import { Alert, ButtonLink, TextLink } from "../../../../../components/ui.tsx";

const ATTEMPT_ID = /^att_[0-9a-f-]{36}$/;
const STEP = /^(0|[1-9][0-9]{0,4})$/;

export const Route = createFileRoute("/_app/runs/$id/logs/$attempt")({
  ssr: "data-only",
  validateSearch: searchSchema({ step: [STEP, 5], seq: [/^(0|[1-9][0-9]{0,15})$/, 16], q: [NO_CONTROL, 256] }),
  loader: async ({ params }) => {
    if (!ATTEMPT_ID.test(params.attempt)) throw notFound();
    try {
      const [run, explain, steps, first] = await Promise.all([
        api<Run>(`/api/v1/runs/${params.id}`),
        api<Explanation>(`/api/v1/runs/${params.id}/pipeline`).catch(() => null),
        api<Steps>(`/api/v1/attempts/${params.attempt}/steps`).catch(() => ({ attempt: params.attempt, present: false }) as Steps),
        // One frame is enough to learn whether retention removed the log.
        api<LogPage>(`/api/v1/attempts/${params.attempt}/logs?limit=1`).catch(() => null),
      ]);
      return { run, explain, steps, expired: first?.expired_ms ?? null };
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 403)) throw notFound();
      throw e;
    }
  },
  head: ({ loaderData, params }) => {
    const job = loaderData?.run.jobs.find((j) => j.attempt === params.attempt);
    return { meta: [{ title: `Log · ${job?.name ?? shortId(params.attempt)} · Sentinel` }] };
  },
  component: LogView,
});


function LogView() {
  const { id: runId, attempt } = Route.useParams();
  const data = Route.useLoaderData();
  const [refused, setRefused] = useState<string | null>(null);
  const job = data.run.jobs.find((j) => j.attempt === attempt) ?? null;
  const spec = data.explain && job ? data.explain.jobs.find((j) => j.name === job.name) : null;
  const stepList = spec ? spec.steps.map((s, index) => ({ index, id: s.id }))
    : data.steps.present ? data.steps.steps.map((s) => ({ index: s.index, id: s.id })) : [{ index: 0, id: "step 0" }];
  // The current attempt's log is live until its end marker is durable.
  const complete = !job || job.log_state === "complete" || (job.terminal && job.log_state === "incomplete");

  return (
    <Page id="log" title={`Log · ${job?.name ?? shortId(attempt)}`} actions={job ? <StateBadge state={job.state} /> : null}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted">
        <TextLink to={`/runs/${runId}`} className="underline">Run {shortId(runId)}</TextLink>
        <span>attempt <code>{shortId(attempt)}</code></span>
        {job && job.attempt !== attempt ? <span>an earlier attempt</span> : null}
        {data.steps.present ? (
          <span>{Object.entries(data.steps.timings_ns).map(([k, v]) => `${words(k)} ${fmtNs(v as number)}`).join(" · ")}</span>
        ) : null}
      </div>
      {refused ? (
        <Alert color="error" icon="lock" title={refused} role="alert">
          <ButtonLink to="/" size="sm" variant="outline" color="neutral" label="Back to your tenants" />
        </Alert>
      ) : null}
      {data.expired ? (
        <Alert color="neutral" icon="archive-x" role="status" title="This log was removed by retention"
          description={`Its storage policy kept it until ${new Date(data.expired).toUTCString()}. The run's result, its steps and their timings are still here.`} />
      ) : (
        <LogPane key={attempt} attempt={attempt} run={runId} steps={stepList} outcomes={data.steps.present ? data.steps.steps : null} complete={complete}
          onRefused={(message) => { setRefused(message); void refreshTenants(); }} />
      )}
    </Page>
  );
}

// Browser only: the viewer measures and scrolls the DOM.
function LogPane(props: { attempt: string; run: string; steps: { index: number; id: string }[]; outcomes: StepRecord[] | null; complete: boolean; onRefused: (m: string) => void }) {
  const host = useRef<HTMLDivElement>(null);
  const viewer = useRef<LogViewer | null>(null);
  const search = Route.useSearch();
  const navigate = useNavigate();
  const latest = useRef(props);
  latest.current = props;

  useEffect(() => {
    const v = new LogViewer(host.current!, {
      attempt: props.attempt,
      run: props.run,
      steps: props.steps,
      outcomes: props.outcomes,
      complete: props.complete,
      page: (q) => api<LogPage>(`/api/v1/attempts/${props.attempt}/logs?${q}`),
      search: (q) => api(`/api/v1/attempts/${props.attempt}/logs/search?${q}`),
      announce,
      refused: (body) => latest.current.onRefused(body?.code === "unauthenticated" ? "Your session ended." : "You no longer have access to this log."),
      linked: (step, seq, q) => {
        const next: Record<string, string> = { step: String(step), seq: String(seq) };
        if (q) next.q = q;
        void navigate({ to: ".", search: next as never, replace: true, resetScroll: false });
      },
    });
    viewer.current = v;
    if (search.seq !== undefined) v.jump(Number(search.step || 0), Number(search.seq), search.q ?? null);
    else if (!props.complete) v.followLive();
    else v.schedule();
    return () => { v.destroy(); viewer.current = null; };
    // One viewer per attempt (the pane is keyed by it).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // A deep link followed while the page is open jumps without a reload.
  const first = useRef(true);
  useEffect(() => {
    if (first.current) { first.current = false; return; }
    if (viewer.current && search.seq !== undefined) viewer.current.jump(Number(search.step || 0), Number(search.seq), search.q ?? null);
  }, [search.step, search.seq, search.q]);

  return <div ref={host} className="log" />;
}
