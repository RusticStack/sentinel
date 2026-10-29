import { useRef, useState } from "react";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { attempt, useLoad, type Load } from "../../lib/loaded.ts";
import { loadRepos, type RepoList } from "../../lib/repos.ts";
import { LoadFailed } from "../LoadFailed.tsx";
import { RelTime } from "../RelTime.tsx";
import { StateBadge } from "../StateBadge.tsx";
import { Button, Select, Table } from "../ui.tsx";
import { confirmChange } from "./Confirm.tsx";

// Values are write-only and never read back: this view lists metadata only.
interface SecretMeta { name: string; version: number; active: boolean; updated_ms: number | null }
interface Binding { job: string | null; step: string | null; name: string; override_tenant?: boolean; from_tenant?: boolean }
interface SecretsScope { secrets: SecretMeta[]; bindings: Binding[] | null }
const TENANT = "__tenant__";
export interface SecretsLoad { repos: Load<RepoList>; scope: Load<SecretsScope> }

async function readScope(slug: string, scope: string): Promise<SecretsScope> {
  const base = `/api/v1/tenants/${encodeURIComponent(slug)}`;
  const q = scope ? `?repo=${encodeURIComponent(scope)}&limit=100` : "?limit=100";
  const secrets = await api<{ secrets: SecretMeta[] }>(`${base}/secrets${q}`);
  const bindings = scope ? await api<{ bindings: Binding[] }>(`${base}/secret-bindings?repo=${encodeURIComponent(scope)}&limit=100`) : null;
  return { secrets: secrets.secrets, bindings: bindings?.bindings ?? null };
}

export async function loadSecrets(slug: string): Promise<SecretsLoad> {
  const [repos, scope] = await Promise.all([attempt(() => loadRepos(slug)), attempt(() => readScope(slug, ""))]);
  return { repos, scope };
}

export function Secrets({ slug, initial }: { slug: string; initial: SecretsLoad }) {
  const { me } = useSession();
  const [scope, setScope] = useState("");
  const { data, setData, failure } = useLoad(initial.scope);
  const latest = useRef("");
  // The tenant scope is the empty repository name; the menu needs a non-empty key for it.
  const scopes = [{ label: "Tenant secrets", value: TENANT }, ...(initial.repos.value?.repos ?? []).map((r) => ({ label: `Repository ${r.name}`, value: r.name }))];
  const refresh = (which = scope) => readScope(slug, which).then(
    (next) => { if (latest.current === which) setData(next); },
    () => { if (latest.current === which) setData(null); },
  );

  function pick(key: string) {
    const next = key === TENANT ? "" : key;
    latest.current = next;
    setScope(next);
    void refresh(next);
  }
  async function remove(s: SecretMeta) {
    const sure = await confirmChange({ title: `Delete ${s.name}?`, description: "Every version is revoked and the name is reserved.", action: "Delete" });
    if (!sure) return;
    const q = scope ? `?repo=${encodeURIComponent(scope)}` : "";
    if (await act(me, `Delete ${s.name}`, () => api(`/api/v1/tenants/${encodeURIComponent(slug)}/secrets/${encodeURIComponent(s.name)}${q}`, {
      method: "DELETE", headers: { "if-match": String(s.version), "idempotency-key": `ui-${crypto.randomUUID()}` },
    }))) await refresh();
  }

  const secrets = data?.secrets ?? [];
  return (
    <section aria-labelledby="secrets-h" className="space-y-3">
      <h2 id="secrets-h" className="text-base font-semibold text-strong">Secrets</h2>
      <p className="text-sm text-muted">Names, versions and where they apply. Values are write-only (<code>sentinel secrets set</code>) and never shown.</p>
      {initial.repos.failure ? <LoadFailed what="the repositories" words={initial.repos.failure} /> : null}
      <Select id="s-scope" label="Scope" ariaLabel="Scope" value={scope || TENANT} onChange={pick} items={scopes} className="w-64 max-w-full" />
      {failure ? <LoadFailed what="the secrets" words={failure} /> : <Table caption="Secrets">
        <thead><tr><th>Name</th><th>Version</th><th>State</th><th>Updated</th><th>Actions</th></tr></thead>
        <tbody>
          {secrets.length ? secrets.map((s) => (
            <tr key={s.name}>
              <td><code className="text-xs">{s.name}</code></td>
              <td>{s.version}</td>
              <td><StateBadge state={s.active ? "online" : "canceled"} label={s.active ? "active" : "revoked"} /></td>
              <td><RelTime ms={s.updated_ms} /></td>
              <td>
                {s.active ? <Button size="sm" color="error" variant="ghost" icon="trash-2" aria-label={`Delete ${s.name}`} onClick={() => void remove(s)}>Delete</Button> : null}
              </td>
            </tr>
          )) : <tr><td colSpan={5} className="text-center text-muted">No secrets in this scope.</td></tr>}
        </tbody>
      </Table>}
      {data?.bindings ? (
        <>
          <h3 className="text-sm font-semibold text-strong">Bindings</h3>
          <Table caption="Bindings">
            <thead><tr><th>Job</th><th>Step</th><th>Variable</th><th>Source</th></tr></thead>
            <tbody>
              {data.bindings.length ? data.bindings.map((b, i) => (
                <tr key={`${b.job}-${b.step}-${b.name}-${i}`}>
                  <td>{b.job || "any"}</td>
                  <td>{b.step || "any"}</td>
                  <td><code className="text-xs">{b.name}</code></td>
                  <td>{b.override_tenant ? "overrides the tenant secret" : b.from_tenant ? "tenant secret" : "repository secret"}</td>
                </tr>
              )) : <tr><td colSpan={4} className="text-center text-muted">No bindings.</td></tr>}
            </tbody>
          </Table>
        </>
      ) : null}
    </section>
  );
}
