import { useState } from "react";
import { api } from "../../lib/api.ts";
import { attempt, useLoad, type Load } from "../../lib/loaded.ts";
import { shortId, words } from "../../lib/format.ts";
import { LoadFailed } from "../LoadFailed.tsx";
import { RelTime } from "../RelTime.tsx";
import { Button, Table, TextLink } from "../ui.tsx";

interface AuditEvent { at_ms: number; action: string; target: string | null; actor: string | null; via: string | null; client?: string | null }
export interface AuditPage { events: AuditEvent[]; next: number | null }
const readAudit = (slug: string, before: number | null) =>
  api<AuditPage>(`/api/v1/tenants/${encodeURIComponent(slug)}/audit?limit=50${before ? `&before=${before}` : ""}`);
export const loadAudit = (slug: string) => attempt(() => readAudit(slug, null));

export function Audit({ slug, initial }: { slug: string; initial: Load<AuditPage> }) {
  const { data, setData, failure } = useLoad(initial);
  const [before, setBefore] = useState<number | null>(null);
  async function show(at: number | null) {
    setBefore(at);
    setData(await readAudit(slug, at).catch(() => null));
  }
  const events = data?.events ?? [];

  return (
    <section aria-labelledby="audit-h" className="space-y-3">
      <h2 id="audit-h" className="text-base font-semibold text-strong">Run control audit</h2>
      {failure ? <LoadFailed what="the audit" words={failure} /> : <Table caption="Audit">
        <thead><tr><th>When</th><th>Action</th><th>Target</th><th>Actor</th><th>Via</th></tr></thead>
        <tbody>
          {events.length ? events.map((e, i) => (
            <tr key={`${e.at_ms}-${i}`}>
              <td><RelTime ms={e.at_ms} /></td>
              <td>{words(e.action)}</td>
              <td>
                {e.target?.startsWith("run_")
                  ? <TextLink to={`/runs/${e.target}`} className="font-mono text-xs underline">{shortId(e.target)}</TextLink>
                  : <code className="text-xs">{shortId(e.target)}</code>}
              </td>
              <td><code className="text-xs">{shortId(e.actor)}</code></td>
              <td>{words(e.via)}{e.client ? ` (${e.client})` : null}</td>
            </tr>
          )) : <tr><td colSpan={5} className="text-center text-muted">Nothing recorded yet.</td></tr>}
        </tbody>
      </Table>}
      <div className="flex gap-2">
        {before ? <Button color="neutral" variant="outline" label="Newest" onClick={() => void show(null)} /> : null}
        {data?.next ? <Button color="neutral" variant="outline" label="Older" trailingIcon="arrow-right" onClick={() => void show(data.next)} /> : null}
      </div>
    </section>
  );
}
