import { useState } from "react";
import type { TenantStorage } from "../../lib/types";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { fmtBytes } from "../../lib/format.ts";
import { StoragePolicyForm, type StoragePolicyBody } from "../StoragePolicyForm.tsx";
import { Button, Card, DialogModal, Table } from "../ui.tsx";

const DAY = 86_400_000;
const readStorage = (slug: string) => api<TenantStorage>(`/api/v1/tenants/${encodeURIComponent(slug)}/storage`);
export const loadStorage = (slug: string) => readStorage(slug).catch(() => null);
const days = (ms: number) => Math.round((ms / DAY) * 10) / 10;

export function Storage({ slug, initial }: { slug: string; initial: TenantStorage | null }) {
  const { me } = useSession();
  const [data, setData] = useLoaded(initial);
  const refresh = () => readStorage(slug).then(setData, () => {});
  const [editing, setEditing] = useState<string | null>(null);

  async function save(repo: string, body: StoragePolicyBody) {
    if (await act(me, `Storage policy of ${repo}`, () => api(`/api/v1/tenants/${encodeURIComponent(slug)}/repos/${encodeURIComponent(repo)}/storage`, { method: "PUT", body }))) {
      setEditing(null);
      await refresh();
    }
  }

  if (!data) return null;
  const total = data.usage.object_bytes + data.usage.log_bytes;
  const quota = data.effective.tenant_quota_bytes ?? 0;
  const edited = editing ? data.repos.find((r) => r.name === editing) : undefined;

  return (
    <section aria-labelledby="storage-h" className="space-y-3">
      <h2 id="storage-h" className="text-base font-semibold text-strong">Storage</h2>
      <div className="grid gap-3 sm:grid-cols-3">
        <Card>
          <p className="text-sm text-muted">Stored</p>
          <p className="text-lg font-semibold text-strong">{fmtBytes(total)}</p>
          <p className="text-xs text-muted">{fmtBytes(data.usage.object_bytes)} objects · {fmtBytes(data.usage.log_bytes)} logs</p>
          {quota ? (
            <div className="mt-2" role="meter" aria-valuenow={Math.min(100, Math.round((100 * total) / quota))} aria-valuemin={0} aria-valuemax={100}
              aria-label={`${fmtBytes(total)} of ${fmtBytes(quota)} quota used`}>
              <div className="h-2 overflow-hidden rounded bg-elevated"><div className="h-full bg-primary" style={{ width: `${Math.min(100, (100 * total) / quota)}%` }} /></div>
              <p className="mt-1 text-xs text-muted">{Math.round((100 * total) / quota)}% of {fmtBytes(quota)}</p>
            </div>
          ) : <p className="mt-2 text-xs text-muted">No quota</p>}
        </Card>
        <Card>
          <p className="text-sm text-muted">Logs kept</p>
          <p className="text-lg font-semibold text-strong">{days(data.effective.log_retention_ms)} days</p>
          <p className="text-xs text-muted">after the attempt finishes</p>
        </Card>
        <Card>
          <p className="text-sm text-muted">Artifacts kept at most</p>
          <p className="text-lg font-semibold text-strong">{days(data.effective.artifact_retention_ms)} days</p>
          <p className="text-xs text-muted">a pipeline's <code>retain</code> is shortened to this</p>
        </Card>
      </div>
      <p className="text-sm text-muted">The platform sets the tenant's limits. Each repository can have its own quota and shorter retention.</p>
      <Table caption="Repository storage">
        <thead><tr><th>Repository</th><th>Artifacts</th><th>Logs</th><th>Quota</th><th>Retention</th><th>Actions</th></tr></thead>
        <tbody>
          {data.repos.length ? data.repos.map((r) => (
            <tr key={r.id}>
              <td>{r.name}</td>
              <td>{fmtBytes(r.usage.artifact_bytes)}</td>
              <td>{fmtBytes(r.usage.log_bytes)}</td>
              <td>{r.effective.repo_quota_bytes ? fmtBytes(r.effective.repo_quota_bytes) : "tenant's"}</td>
              <td>logs {days(r.effective.log_retention_ms)}d · artifacts {days(r.effective.artifact_retention_ms)}d</td>
              <td>
                <Button size="sm" color="neutral" variant="outline" icon="sliders-horizontal" aria-label={`Storage policy of ${r.name}`} onClick={() => setEditing(r.name)}>Policy</Button>
              </td>
            </tr>
          )) : <tr><td colSpan={6} className="text-center text-muted">No data</td></tr>}
        </tbody>
      </Table>
      <DialogModal isOpen={!!edited} onClose={() => setEditing(null)} title={`Storage policy · ${editing}`} description="Blank fields inherit the tenant's limits.">
        {edited ? (
          <StoragePolicyForm id={`repo-${edited.name}`} policy={edited.policy}
            inherited={{ quota_bytes: 0, log_retention_ms: data.effective.log_retention_ms, artifact_retention_ms: data.effective.artifact_retention_ms }}
            maxLogDays={data.effective.log_retention_ms / DAY} maxArtifactDays={data.effective.artifact_retention_ms / DAY}
            onSave={(body) => void save(edited.name, body)} />
        ) : null}
      </DialogModal>
    </section>
  );
}
