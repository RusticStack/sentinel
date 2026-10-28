import { createFileRoute } from "@tanstack/react-router";
import { api } from "../../../../lib/api.ts";
import { cpu, fmtBytes, fmtMs, shortId, words } from "../../../../lib/format.ts";
import { loadRepos } from "../../../../lib/repos.ts";
import { useLoaded } from "../../../../lib/hooks.ts";
import { Page } from "../../../../components/Page.tsx";
import { Alert, Badge, Table, TextLink, useInterval } from "../../../../components/ui.tsx";

const REASONS: Record<string, string> = {
  dependency: "waiting for jobs it needs",
  policy: "held by policy",
  no_matching_worker: "no worker is large enough",
  disk_short: "no worker has the scratch space",
  worker_offline: "matching workers are offline",
  capacity: "matching workers are busy",
  arch_mismatch: "no worker has this architecture",
  label_missing: "no worker has the required labels",
  drain: "matching workers are draining",
  concurrency_limit: "its concurrency group is full",
  fairness_hold: "held for fairness to other work",
  locality_wait: "waiting for a worker with warm caches",
  ready: "ready: the next placement pass takes it",
  storage: "new work is paused",
};
const STORAGE: Record<string, string> = {
  disk_below_watermark: "the controller's disk is below its low watermark",
  external_copy_backlog: "the external S3 copy is behind; it resumes once the backlog drains",
};

interface Waiting { job: string; run: string; repo: string; age_ms: number; reason: { code: string; detail?: string; cpu_short?: number; memory_short?: number; disk_short?: number } }
interface Queue { jobs: Waiting[]; total: number; truncated: boolean; placement_paused: string | null }

function explain(r: Waiting["reason"]) {
  const parts = [REASONS[r.code] ?? words(r.code)];
  if (r.code === "storage") parts.push(`: ${STORAGE[r.detail ?? ""] ?? words(r.detail)}`);
  else if (r.detail) parts.push(`(${r.detail})`);
  if (r.cpu_short) parts.push(`— short ${cpu(r.cpu_short)}`);
  if (r.memory_short) parts.push(`— short ${fmtBytes(r.memory_short)} memory`);
  if (r.disk_short) parts.push(`— short ${fmtBytes(r.disk_short)} disk`);
  return parts.join(" ");
}

const readQueue = (slug: string) => api<Queue>(`/api/v1/queue?tenant=${encodeURIComponent(slug)}&limit=200`);

export const Route = createFileRoute("/_app/t/$slug/queue")({
  loader: async ({ params }) => {
    const [repos, queue] = await Promise.all([loadRepos(params.slug), readQueue(params.slug)]);
    return { repos, queue };
  },
  head: ({ params }) => ({ meta: [{ title: `Queue · ${params.slug} · Sentinel` }] }),
  component: QueueView,
});

function QueueView() {
  const { slug } = Route.useParams();
  const loaded = Route.useLoaderData();
  const [queue, setQueue] = useLoaded(loaded.queue);
  const names = new Map(loaded.repos.repos.map((r) => [r.id, r.name]));
  useInterval(() => { readQueue(slug).then(setQueue, () => {}); }, 5000);

  return (
    <Page id="queue" title={`Queue · ${slug}`}>
      <p className="text-sm text-muted">
        {queue.total} waiting job{queue.total === 1 ? "" : "s"}{queue.truncated ? `; the oldest ${queue.jobs.length} are shown` : ""}. Refreshes every 5 s.
      </p>
      {queue.placement_paused ? (
        <Alert color="warning" icon="hard-drive" role="status" title="No new work is being placed"
          description={`The controller paused placement: ${STORAGE[queue.placement_paused] ?? words(queue.placement_paused)}.`} />
      ) : null}
      <Table caption="Waiting jobs">
        <thead><tr><th>Job</th><th>Run</th><th>Repository</th><th>Waiting</th><th>Reason</th></tr></thead>
        <tbody>
          {queue.jobs.length ? queue.jobs.map((j) => (
            <tr key={j.job}>
              <td><code className="text-xs">{shortId(j.job)}</code></td>
              <td><TextLink to={`/runs/${j.run}`} className="underline">{shortId(j.run)}</TextLink></td>
              <td>{names.get(j.repo) ?? shortId(j.repo)}</td>
              <td>{fmtMs(j.age_ms)}</td>
              <td>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge color={j.reason.code === "ready" ? "info" : "warning"}>{words(j.reason.code)}</Badge>
                  <span>{explain(j.reason)}</span>
                </div>
              </td>
            </tr>
          )) : <tr><td colSpan={5} className="text-center text-muted">Nothing is waiting.</td></tr>}
        </tbody>
      </Table>
    </Page>
  );
}
