import { useState } from "react";
import type { DeploymentStorage } from "../../lib/types";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { refreshTenants, useSession } from "../../lib/session.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { fmtBytes } from "../../lib/format.ts";
import { StateBadge } from "../StateBadge.tsx";
import { StoragePolicyForm, type StoragePolicyBody } from "../StoragePolicyForm.tsx";
import { Button, DialogModal, Field, Input, Table, TextLink } from "../ui.tsx";
import { confirmChange } from "../admin/Confirm.tsx";

interface TenantRow {
  slug: string; kind: string; active: boolean; members: number; usage_bytes: number;
  quota_bytes: number | null; quota_set: boolean; log_retention_ms?: number | null; artifact_retention_ms?: number | null;
}
export interface TenantsPage { tenants: TenantRow[]; next: string | null }
export interface TenantsLoad { page: TenantsPage | null; deployment: DeploymentStorage | null }

const readTenants = (after: string | null) => api<TenantsPage>(`/api/v1/admin/tenants?limit=50${after ? `&after=${encodeURIComponent(after)}` : ""}`);
export async function loadTenants(): Promise<TenantsLoad> {
  const [page, deployment] = await Promise.all([readTenants(null).catch(() => null), api<DeploymentStorage>("/api/v1/admin/storage").catch(() => null)]);
  return { page, deployment };
}

export function Tenants({ initial }: { initial: TenantsLoad }) {
  const { me } = useSession();
  const [data, setData] = useLoaded(initial.page);
  const [after, setAfter] = useState<string | null>(null);
  const refresh = (at = after) => readTenants(at).then(setData, () => {});
  const deployment = initial.deployment;
  const [quotas, setQuotas] = useState<Record<string, string>>({});
  const [slug, setSlug] = useState("");
  const [editing, setEditing] = useState<TenantRow | null>(null);

  function page(at: string | null) {
    setAfter(at);
    void refresh(at);
  }
  async function saveStorage(t: TenantRow, body: StoragePolicyBody) {
    if (await act(me, `Storage policy of ${t.slug}`, () => api(`/api/v1/admin/tenants/${t.slug}/storage`, { method: "PUT", body }))) {
      setEditing(null);
      await refresh();
    }
  }
  async function setQuota(e: React.FormEvent, t: TenantRow) {
    e.preventDefault();
    const gib = Number(quotas[t.slug] ?? "");
    if (!gib || gib <= 0 || !Number.isFinite(gib)) return;
    await act(me, `Quota of ${t.slug}`, () => api(`/api/v1/admin/tenants/${t.slug}/quota`, { method: "PUT", body: { bytes: Math.round(Math.max(1, gib) * 2 ** 30) } }));
    await refresh();
  }
  async function clearQuota(t: TenantRow) {
    await act(me, `Default quota of ${t.slug}`, () => api(`/api/v1/admin/tenants/${t.slug}/quota`, { method: "DELETE" }));
    await refresh();
  }
  async function toggle(t: TenantRow) {
    if (await act(me, `${t.active ? "Suspend" : "Reactivate"} ${t.slug}`, () => api(`/api/v1/admin/tenants/${t.slug}/${t.active ? "suspend" : "reactivate"}`, { method: "POST", body: {} }))) {
      await refresh();
      await refreshTenants();
    }
  }
  async function suspend(t: TenantRow) {
    const sure = await confirmChange({
      title: `Suspend ${t.slug}?`, description: "Its credentials and invitations are revoked, its jobs are cancelled, and its members lose access at once.",
      action: "Suspend", keep: "Keep active",
    });
    if (sure) await toggle(t);
  }
  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (await act(me, `Create ${slug}`, () => api("/api/v1/admin/tenants", { method: "POST", body: { slug } }))) {
      setSlug("");
      await refresh();
    }
  }

  const tenants = data?.tenants ?? [];
  return (
    <>
      <section aria-labelledby="tenants-h" className="space-y-3">
        <h2 id="tenants-h" className="text-base font-semibold text-strong">Tenants</h2>
        <Table caption="Tenants">
          <thead><tr><th>Tenant</th><th>Kind</th><th>State</th><th>Members</th><th>Storage</th><th>Quota</th><th>Actions</th></tr></thead>
          <tbody>
            {tenants.length ? tenants.map((t) => (
              <tr key={t.slug}>
                <td>
                  {t.active
                    ? <TextLink to={`/t/${t.slug}/admin`} className="font-medium underline">{t.slug}</TextLink>
                    : <span className="font-medium text-strong">{t.slug}</span>}
                </td>
                <td>{t.kind}</td>
                <td><StateBadge state={t.active ? "online" : "suspended"} label={t.active ? "active" : "suspended"} /></td>
                <td>{t.members}</td>
                <td>{fmtBytes(t.usage_bytes)}</td>
                <td>
                  <form className="flex items-center gap-2" onSubmit={(e) => void setQuota(e, t)}>
                    <Input type="number" inputMode="decimal" min={1} step="any" value={quotas[t.slug] ?? ""} onChange={(e) => setQuotas({ ...quotas, [t.slug]: e.target.value })}
                      placeholder={t.quota_bytes ? (t.quota_bytes / 2 ** 30).toFixed(0) : "unlimited"} aria-label={`Quota of ${t.slug} in GiB`} className="w-40" />
                    <span className="text-sm text-muted">GiB</span>
                    <Button type="submit" size="sm" color="neutral" variant="outline" label="Set" />
                    {t.quota_set ? <Button size="sm" color="neutral" variant="ghost" label="Default" onClick={() => void clearQuota(t)} /> : null}
                  </form>
                  <p className="mt-1 text-xs text-muted">{t.quota_bytes ? `${Math.round((100 * t.usage_bytes) / t.quota_bytes)}% of ${fmtBytes(t.quota_bytes)} used` : "no limit"}</p>
                </td>
                <td>
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" color="neutral" variant="outline" icon="sliders-horizontal" aria-label={`Storage policy of ${t.slug}`} onClick={() => setEditing(t)}>Storage</Button>
                    {t.active
                      ? <Button size="sm" color="error" variant="soft" icon="pause" aria-label={`Suspend ${t.slug}`} onClick={() => void suspend(t)}>Suspend</Button>
                      : <Button size="sm" icon="play" aria-label={`Reactivate ${t.slug}`} onClick={() => void toggle(t)}>Reactivate</Button>}
                  </div>
                </td>
              </tr>
            )) : <tr><td colSpan={7} className="text-center text-muted">No data</td></tr>}
          </tbody>
        </Table>
        <div className="flex gap-2">
          {after ? <Button color="neutral" variant="outline" label="First page" onClick={() => page(null)} /> : null}
          {data?.next ? <Button color="neutral" variant="outline" label="Next page" trailingIcon="arrow-right" onClick={() => page(data.next)} /> : null}
        </div>
      </section>
      <section aria-labelledby="new-tenant-h" className="space-y-3">
        <h2 id="new-tenant-h" className="text-base font-semibold text-strong">Create an organization</h2>
        <form className="flex flex-wrap items-end gap-3" aria-label="Create an organization" onSubmit={create}>
          <Field label="Slug" htmlFor="t-slug" help="Lowercase letters, digits and inner hyphens">
            <Input id="t-slug" name="slug" value={slug} onChange={(e) => setSlug(e.target.value)} required className="w-56 max-w-full" />
          </Field>
          <Button type="submit" icon="plus" label="Create" />
        </form>
        <p className="text-sm text-muted">A new organization has no members: add its first administrator from its Tenant admin page.</p>
      </section>
      <DialogModal isOpen={!!editing} onClose={() => setEditing(null)} title={`Storage policy · ${editing?.slug}`} description="Blank fields inherit the deployment's configuration.">
        {editing ? (
          <StoragePolicyForm id={`tenant-${editing.slug}`}
            policy={{ quota_bytes: editing.quota_set ? editing.quota_bytes : null, log_retention_ms: editing.log_retention_ms ?? null, artifact_retention_ms: editing.artifact_retention_ms ?? null }}
            inherited={{ quota_bytes: deployment?.tenant_quota_bytes ?? 0, log_retention_ms: deployment?.log_retention_ms ?? 14 * 86_400_000, artifact_retention_ms: deployment?.artifact_retention_ms ?? 90 * 86_400_000 }}
            onSave={(body) => void saveStorage(editing, body)} />
        ) : null}
      </DialogModal>
    </>
  );
}
