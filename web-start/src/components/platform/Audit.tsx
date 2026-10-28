import { useState } from "react";
import { api } from "../../lib/api.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { shortId, words } from "../../lib/format.ts";
import { RelTime } from "../RelTime.tsx";
import { Button, Table } from "../ui.tsx";

interface AuthEvent { at_ms: number; event: string; actor: string | null; host_local?: boolean; subject: string | null; detail?: string | null }
export interface PlatformAuditPage { events: AuthEvent[]; next: number | null }
const readAudit = (before: number | null) => api<PlatformAuditPage>(`/api/v1/admin/audit?limit=50${before ? `&before=${before}` : ""}`);
export const loadPlatformAudit = () => readAudit(null).catch(() => null);

export function Audit({ initial }: { initial: PlatformAuditPage | null }) {
  const [data, setData] = useLoaded(initial);
  const [before, setBefore] = useState<number | null>(null);
  async function show(at: number | null) {
    setBefore(at);
    setData(await readAudit(at).catch(() => null));
  }
  const events = data?.events ?? [];

  return (
    <section aria-labelledby="paudit-h" className="space-y-3">
      <h2 id="paudit-h" className="text-base font-semibold text-strong">Authentication and administration audit</h2>
      <Table caption="Audit">
        <thead><tr><th>When</th><th>Event</th><th>Actor</th><th>Subject</th><th>Detail</th></tr></thead>
        <tbody>
          {events.length ? events.map((e, i) => (
            <tr key={`${e.at_ms}-${i}`}>
              <td><RelTime ms={e.at_ms} /></td>
              <td>{words(e.event.replace(/-/g, "_"))}</td>
              <td><code className="text-xs">{e.host_local ? "host" : shortId(e.actor)}</code></td>
              <td><code className="text-xs">{shortId(e.subject)}</code></td>
              <td>{e.detail ?? ""}</td>
            </tr>
          )) : <tr><td colSpan={5} className="text-center text-muted">No data</td></tr>}
        </tbody>
      </Table>
      <div className="flex gap-2">
        {before ? <Button color="neutral" variant="outline" label="Newest" onClick={() => void show(null)} /> : null}
        {data?.next ? <Button color="neutral" variant="outline" label="Older" trailingIcon="arrow-right" onClick={() => void show(data.next)} /> : null}
      </div>
    </section>
  );
}
