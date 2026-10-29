import { useState } from "react";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { Badge, Button, Field, Icon, Input, Select, Table } from "../ui.tsx";

interface PoolRow { id: string; name: string; kind: "shared" | "dedicated"; active: boolean; workers: number; owner?: string | null; grants: string[] }
export interface PoolsPage { pools: PoolRow[] }
const readPools = () => api<PoolsPage>("/api/v1/admin/pools");
export const loadPools = () => readPools().catch(() => null);
const KINDS = [{ label: "Shared", value: "shared" }, { label: "Dedicated", value: "dedicated" }];

export function Pools({ initial }: { initial: PoolsPage | null }) {
  const { me } = useSession();
  const [data, setData] = useLoaded(initial);
  const refresh = () => readPools().then(setData, () => {});
  const [form, setForm] = useState({ name: "", kind: "shared", tenant: "" });
  const [grantTo, setGrantTo] = useState<Record<string, string>>({});

  async function create(e: React.FormEvent) {
    e.preventDefault();
    const body: Record<string, string> = { name: form.name, kind: form.kind };
    if (form.kind === "dedicated") body.tenant = form.tenant;
    if (await act(me, `Create ${form.name}`, () => api("/api/v1/admin/pools", { method: "POST", body }))) {
      setForm((f) => ({ ...f, name: "" }));
      await refresh();
    }
  }
  async function grant(p: PoolRow, slug: string, on: boolean) {
    if (await act(me, `${on ? "Grant" : "Revoke"} ${p.name} ${on ? "to" : "from"} ${slug}`, () => api(`/api/v1/admin/pools/${p.id}/grants/${encodeURIComponent(slug)}`, { method: on ? "PUT" : "DELETE" }))) {
      setGrantTo((g) => ({ ...g, [p.id]: "" }));
      await refresh();
    }
  }

  const pools = data?.pools ?? [];
  return (
    <>
      <section aria-labelledby="pools-h" className="space-y-3">
        <h2 id="pools-h" className="text-base font-semibold text-strong">Worker pools</h2>
        <Table caption="Pools">
          <thead><tr><th>Pool</th><th>Kind</th><th>Workers</th><th>Tenants</th><th>Grant</th></tr></thead>
          <tbody>
            {pools.length ? pools.map((p) => (
              <tr key={p.id}>
                <td><span className="font-medium text-strong">{p.name}</span>{!p.active ? <Badge color="warning" className="ml-2">inactive</Badge> : null}</td>
                <td>{p.kind}</td>
                <td>{p.workers}</td>
                <td>
                  {p.kind === "dedicated" ? <span>owned by {p.owner}</span> : (
                    <div className="flex flex-wrap gap-1">
                      {p.grants.map((slug) => (
                        <Badge key={slug} className="border border-line">
                          {slug}
                          <button type="button" className="ml-1 cursor-pointer text-error" aria-label={`Revoke ${p.name} from ${slug}`} onClick={() => void grant(p, slug, false)}>
                            <Icon name="x" className="size-3.5" />
                          </button>
                        </Badge>
                      ))}
                      {!p.grants.length ? <span className="text-muted">none</span> : null}
                    </div>
                  )}
                </td>
                <td>
                  {p.kind === "shared" ? (
                    <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); void grant(p, grantTo[p.id] || "", true); }}>
                      <Input value={grantTo[p.id] ?? ""} onChange={(e) => setGrantTo({ ...grantTo, [p.id]: e.target.value })} placeholder="tenant slug"
                        aria-label={`Tenant to grant ${p.name}`} className="w-36 py-1" />
                      <Button type="submit" size="sm" color="neutral" variant="outline" label="Grant" />
                    </form>
                  ) : null}
                </td>
              </tr>
            )) : <tr><td colSpan={5} className="text-center text-muted">No data</td></tr>}
          </tbody>
        </Table>
      </section>
      <section aria-labelledby="new-pool-h" className="space-y-3">
        <h2 id="new-pool-h" className="text-base font-semibold text-strong">Create a pool</h2>
        <form className="flex flex-wrap items-end gap-3" aria-label="Create a pool" onSubmit={create}>
          <Field label="Name" htmlFor="p-name">
            <Input id="p-name" name="p-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required maxLength={64} className="w-48 max-w-full" />
          </Field>
          <Select id="p-kind" label="Kind" ariaLabel="Kind" value={form.kind} onChange={(kind) => setForm({ ...form, kind })} items={KINDS} className="w-36" />
          {form.kind === "dedicated" ? (
            <Field label="Owner tenant" htmlFor="p-owner">
              <Input id="p-owner" name="p-owner" value={form.tenant} onChange={(e) => setForm({ ...form, tenant: e.target.value })} required className="w-40 max-w-full" />
            </Field>
          ) : null}
          <Button type="submit" icon="plus" label="Create" />
        </form>
      </section>
    </>
  );
}
