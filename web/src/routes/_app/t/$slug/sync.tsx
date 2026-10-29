import { createFileRoute } from "@tanstack/react-router";
import type { RepoSync } from "../../../../lib/types";
import { api } from "../../../../lib/api.ts";
import { useLoaded } from "../../../../lib/hooks.ts";
import { fmtMs } from "../../../../lib/format.ts";
import { Page } from "../../../../components/Page.tsx";
import { RelTime } from "../../../../components/RelTime.tsx";
import { Badge, Table, useInterval } from "../../../../components/ui.tsx";

interface SyncPage { now_ms: number; repos: RepoSync[]; next: string | null }
const readSync = (slug: string) => api<SyncPage>(`/api/v1/tenants/${encodeURIComponent(slug)}/sync?limit=100`);

export const Route = createFileRoute("/_app/t/$slug/sync")({
  loader: async ({ params }) => ({ sync: await readSync(params.slug).catch(() => null) }),
  head: ({ params }) => ({ meta: [{ title: `GitHub sync · ${params.slug} · Sentinel` }] }),
  component: SyncView,
});

function SyncView() {
  const { slug } = Route.useParams();
  const loaded = Route.useLoaderData();
  const [data, setData] = useLoaded(loaded.sync);
  useInterval(() => { readSync(slug).then(setData, () => {}); }, 10000);
  // Ages are measured against the controller's clock, so the server render and the browser agree.
  const lag = (since: number | null) => (since && data ? data.now_ms - since : null);
  const repos = data?.repos ?? [];

  return (
    <Page id="sync" title={`GitHub sync · ${slug}`}>
      <p className="text-sm text-muted">Refreshes every 10 s. A check pending for more than a minute is marked.</p>
      <Table caption="Synchronization by repository">
        <thead>
          <tr><th>Repository</th><th>Pending checks</th><th>Oldest pending</th><th>Refused (24 h)</th><th>Last published</th><th>Open deliveries</th><th>Oldest delivery</th></tr>
        </thead>
        <tbody>
          {repos.length ? repos.map((r) => {
            const oldest = lag(r.oldest_pending_ms);
            return (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td>{r.pending}</td>
                <td>{oldest !== null ? <Badge color={oldest > 60000 ? "error" : "neutral"}>{fmtMs(oldest)}</Badge> : <span className="text-muted">—</span>}</td>
                <td>{r.refused ? <Badge color="error">{String(r.refused)}</Badge> : <span>0</span>}</td>
                <td><RelTime ms={r.last_published_ms} /></td>
                <td>{r.open_deliveries}</td>
                <td>{r.oldest_delivery_ms ? fmtMs(lag(r.oldest_delivery_ms)) : "—"}</td>
              </tr>
            );
          }) : <tr><td colSpan={7} className="text-center text-muted">No data</td></tr>}
        </tbody>
      </Table>
      {data?.next ? <p className="text-sm text-muted">Only the first 100 repositories are shown.</p> : null}
    </Page>
  );
}
