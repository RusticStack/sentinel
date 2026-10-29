import { createFileRoute } from "@tanstack/react-router";
import type { Pool, Worker } from "../../../../lib/types";
import { api } from "../../../../lib/api.ts";
import { act } from "../../../../lib/act.tsx";
import { useSession } from "../../../../lib/session.ts";
import { useLoaded } from "../../../../lib/hooks.ts";
import { cpu, fmtBytes, fmtNs, shortId } from "../../../../lib/format.ts";
import { Page } from "../../../../components/Page.tsx";
import { RelTime } from "../../../../components/RelTime.tsx";
import { StateBadge } from "../../../../components/StateBadge.tsx";
import { Badge, Button, Empty, Table, useInterval } from "../../../../components/ui.tsx";

// Reserved figures are totals: a shared worker also serves other tenants.
const readWorkers = (slug: string) => api<{ pools: Pool[] }>(`/api/v1/workers?tenant=${encodeURIComponent(slug)}`);

export const Route = createFileRoute("/_app/t/$slug/workers")({
  loader: async ({ params }) => ({ workers: await readWorkers(params.slug).catch(() => null) }),
  head: ({ params }) => ({ meta: [{ title: `Workers · ${params.slug} · Sentinel` }] }),
  component: WorkersView,
});

const used = (w: Worker) => (w.capacity?.cpu_millis ? Math.min(100, Math.round((100 * w.held.cpu_millis) / w.capacity.cpu_millis)) : null);
const disk = (bytes: number) => (bytes === 0 ? "no scratch disk; cannot accept jobs" : `${fmtBytes(bytes)} disk`);

function WorkersView() {
  const { slug } = Route.useParams();
  const loaded = Route.useLoaderData();
  const { me } = useSession();
  const [data, setData] = useLoaded(loaded.workers);
  const refresh = () => readWorkers(slug).then(setData, () => {});
  useInterval(() => { void refresh(); }, 5000);

  async function drain(w: Worker) {
    await act(me, `${w.draining ? "Undrain" : "Drain"} ${w.name}`, () => api(`/api/v1/workers/${w.id}/${w.draining ? "undrain" : "drain"}`, { method: "POST", body: {} }));
    await refresh();
  }

  return (
    <Page id="workers" title={`Workers · ${slug}`}>
      {data && !data.pools.length ? <Empty icon="server-off" title="No worker pools" description="This tenant has no dedicated or granted pools." /> : null}
      {(data?.pools ?? []).map((pool) => (
        <section key={pool.id} aria-labelledby={`pool-${pool.id}`} className="min-w-0 space-y-3">
          <h2 id={`pool-${pool.id}`} className="flex items-center gap-2 text-base font-semibold text-strong">
            {pool.name}
            <Badge>{`${pool.kind} pool`}</Badge>
            {!pool.active ? <Badge color="warning">inactive</Badge> : null}
          </h2>
          <Table caption={`Workers in ${pool.name}`}>
            <thead>
              <tr><th>Worker</th><th>State</th><th>Capacity</th><th>Held</th><th>Free on host</th><th>Labels</th><th>Cache</th><th>Transport</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {pool.workers.length ? pool.workers.map((w) => {
                const pct = used(w);
                return (
                  <tr key={w.id}>
                    <td>
                      <div className="font-medium text-strong">{w.name}</div>
                      <div className="font-mono text-xs text-muted">{w.arch} · {shortId(w.id)}</div>
                      <div className="text-xs text-muted">{w.software ?? "software not reported"} · protocol {w.protocol}</div>
                    </td>
                    <td>
                      <StateBadge state={!w.connected ? "offline" : w.draining ? "draining" : "online"} />
                      {!w.connected ? <div className="mt-1 text-xs text-muted">seen <RelTime ms={w.last_seen_ms} /></div> : null}
                    </td>
                    <td>
                      {w.capacity
                        ? <span>{cpu(w.capacity.cpu_millis)}, {fmtBytes(w.capacity.memory_bytes)}{w.capacity.disk_bytes !== undefined ? `, ${disk(w.capacity.disk_bytes)}` : null}</span>
                        : <span className="text-muted">not reported</span>}
                    </td>
                    <td>
                      <div>{w.held_attempts} attempt{w.held_attempts === 1 ? "" : "s"}</div>
                      <div className="text-xs text-muted">{cpu(w.held.cpu_millis)}, {fmtBytes(w.held.memory_bytes)}</div>
                      {pct !== null ? (
                        <div className="mt-1 h-1.5 w-28 overflow-hidden rounded-full bg-elevated" role="img" aria-label={`${pct}% of CPU reserved`}>
                          <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
                        </div>
                      ) : null}
                    </td>
                    <td>
                      {cpu(w.free.cpu_millis)}, {fmtBytes(w.free.memory_bytes)}{w.free.disk_bytes !== undefined ? `, ${disk(w.free.disk_bytes)}` : null}
                      {(w.host_workers ?? 0) > 1 ? <div className="text-xs text-muted">host shared by {w.host_workers} workers</div> : null}
                    </td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {w.labels.map((l) => <Badge key={l} className="border border-line">{l}</Badge>)}
                        {!w.labels.length ? <span className="text-muted">—</span> : null}
                      </div>
                    </td>
                    <td>{w.cache_bytes ? fmtBytes(w.cache_bytes) : "—"}</td>
                    <td>
                      {w.transport ? (
                        <>
                          {w.transport.path}{w.transport.rtt_ns ? `, ${fmtNs(w.transport.rtt_ns)} RTT` : null}
                          {w.transport.reconnects ? <div className="text-xs text-muted">{w.transport.reconnects} reconnects</div> : null}
                        </>
                      ) : <span className="text-muted">—</span>}
                    </td>
                    <td>
                      {me?.super_admin ? (
                        <Button size="sm" color="neutral" variant="outline" icon={w.draining ? "play" : "pause"} aria-label={`${w.draining ? "Undrain" : "Drain"} ${w.name}`}
                          onClick={() => void drain(w)}>
                          {w.draining ? "Undrain" : "Drain"}
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                );
              }) : <tr><td colSpan={9} className="text-center text-muted">No workers enrolled.</td></tr>}
            </tbody>
          </Table>
        </section>
      ))}
    </Page>
  );
}
