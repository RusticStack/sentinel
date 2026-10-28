import { useState } from "react";
import type { Grant, Member } from "../../lib/types";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { useOverride } from "../../lib/override.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { loadRepos, type RepoList } from "../../lib/repos.ts";
import { shortId } from "../../lib/format.ts";
import { showOnce } from "../ShowOnceDialog.tsx";
import { RelTime } from "../RelTime.tsx";
import { Badge, Button, Empty, Field, Icon, Input, Select, Table } from "../ui.tsx";
import { CheckboxGroup } from "./CheckboxGroup.tsx";
import { confirmChange } from "./Confirm.tsx";

// The refresh token is shown once and never again.
interface Accounts { accounts: Member[]; partial: boolean }
export interface ServiceAccountsLoad { accounts: Accounts | null; repos: RepoList | null }

const ROLES = [{ label: "Operator (runs)", value: "operator" }, { label: "Reader", value: "reader" }];
const ACCESS = [{ label: "Read", value: "read" }, { label: "Run", value: "run" }];
const SCOPES = ["runs:read", "runs:write", "logs:read", "artifacts:read", "cache:read", "cache:write", "secrets:metadata", "secrets:write"]
  .map((s) => ({ label: s, value: s }));
const HOUR = 3600e3;
const LIFETIMES = [
  { label: "1 hour", value: HOUR }, { label: "1 day", value: 24 * HOUR }, { label: "7 days", value: 7 * 24 * HOUR },
  { label: "30 days", value: 30 * 24 * HOUR }, { label: "90 days", value: 90 * 24 * HOUR },
].map((l) => ({ label: l.label, value: String(l.value) }));
const ANY_REPO = "__any__";

async function readAccounts(slug: string): Promise<Accounts> {
  const page = await api<{ members: Member[]; next: string | null }>(`/api/v1/tenants/${encodeURIComponent(slug)}/members?limit=100`);
  return { accounts: page.members.filter((m) => m.kind === "service"), partial: !!page.next };
}

export async function loadServiceAccounts(slug: string): Promise<ServiceAccountsLoad> {
  const [accounts, repos] = await Promise.all([readAccounts(slug).catch(() => null), loadRepos(slug).catch(() => null)]);
  return { accounts, repos };
}

export function ServiceAccounts({ slug, initial }: { slug: string; initial: ServiceAccountsLoad }) {
  const { me } = useSession();
  const { ready, withReason } = useOverride(slug);
  const [data, setData] = useLoaded(initial.accounts);
  const refresh = () => readAccounts(slug).then(setData, () => {});
  const repos = initial.repos?.repos ?? [];
  const [name, setName] = useState("");
  const [role, setRole] = useState("operator");

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!ready()) return;
    const body = withReason({ name: name.trim(), role });
    if (await act(me, `Create ${body.name}`, () => api(`/api/v1/tenants/${encodeURIComponent(slug)}/service-accounts`, { method: "POST", body }))) {
      setName("");
      await refresh();
    }
  }

  return (
    <>
      <section aria-labelledby="sa-h" className="space-y-3">
        <h2 id="sa-h" className="text-base font-semibold text-strong">Service accounts</h2>
        <p className="text-sm text-muted">Automation that runs pipelines or reads results without a person's account. Each credential is a refresh token the agent imports; it lasts until it expires or is revoked.</p>
        {!data?.accounts.length ? (
          <Empty icon="bot" title="No service accounts yet" description="Create one below, give it access to a repository, then issue it a credential." />
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">
            {data.accounts.map((m) => <AccountCard key={m.user} slug={slug} account={m} repos={repos} />)}
          </div>
        )}
        {data?.partial ? <p className="text-sm text-muted">Only service accounts among the first 100 members are shown.</p> : null}
      </section>

      <section aria-labelledby="sa-new-h" className="space-y-3">
        <h2 id="sa-new-h" className="text-base font-semibold text-strong">Create a service account</h2>
        <form className="flex flex-wrap items-end gap-3" aria-label="Create a service account" onSubmit={create}>
          <Field label="Name" htmlFor="sa-name">
            <Input id="sa-name" name="sa-name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={128} autoComplete="off" className="w-56 max-w-full" />
          </Field>
          <Select id="sa-role" label="Role" ariaLabel="Role" value={role} onChange={setRole} items={ROLES} className="w-44" />
          <Button type="submit" icon="plus" label="Create" />
        </form>
      </section>
    </>
  );
}

function AccountCard({ slug, account: m, repos }: { slug: string; account: Member; repos: { id: string; name: string }[] }) {
  const { me } = useSession();
  const { ready, withReason } = useOverride(slug);
  const repoItems = repos.map((r) => ({ label: r.name, value: r.name }));
  const repoName = (id: string | null) => (id ? repos.find((r) => r.id === id)?.name ?? shortId(id) : "every repository it may use");
  const base = `/api/v1/tenants/${encodeURIComponent(slug)}/service-accounts/${m.user}`;

  const [accessRepo, setAccessRepo] = useState(repoItems[0]?.value ?? "");
  const [access, setAccess] = useState<string[]>(["read", "run"]);
  const [grantName, setGrantName] = useState("");
  const [scope, setScope] = useState<string[]>(["runs:read", "runs:write", "logs:read"]);
  const [grantRepo, setGrantRepo] = useState(ANY_REPO);
  const [lifetime, setLifetime] = useState(String(30 * 24 * HOUR));
  const [grants, setGrants] = useState<Grant[] | null>(null);

  async function setRepoAccess(e: React.FormEvent) {
    e.preventDefault();
    if (!accessRepo || !ready()) return;
    await act(me, `Access of ${m.display_name} to ${accessRepo}`, () => api(`${base}/repos/${encodeURIComponent(accessRepo)}`, { method: "PUT", body: withReason({ access }) }));
  }
  async function loadGrants() {
    const list = await act(me, `Credentials of ${m.display_name}`, () => api<{ grants: Grant[] }>(`${base}/grants`), false);
    if (list) setGrants(list.grants);
  }
  async function toggleGrants() {
    if (grants) setGrants(null);
    else await loadGrants();
  }
  async function issueGrant(e: React.FormEvent) {
    e.preventDefault();
    if (!scope.length || !ready()) return;
    const body = withReason({
      name: grantName.trim(),
      scope: scope.join(" "),
      expires_in_ms: Number(lifetime),
      ...(grantRepo === ANY_REPO ? {} : { repo: grantRepo }),
    });
    const issued = await act(me, `Credential ${body.name} for ${m.display_name}`, () =>
      api<{ grant: string; refresh_token: string; expires_ms: number }>(`${base}/grants`, { method: "POST", body }));
    if (!issued) return;
    setGrantName("");
    await showOnce({
      title: `Credential for ${m.display_name}`,
      description: `A refresh token for ${body.scope}, valid until ${new Date(issued.expires_ms).toISOString().slice(0, 10)}. It is shown this once.`,
      secrets: [issued.refresh_token],
      filename: `${m.display_name.replace(/[^A-Za-z0-9._-]+/g, "-")}.token`,
      note: "On the agent's machine: sentinel auth login --grant-file <file>. Importing spends it, so the file can be deleted afterwards.",
    });
    if (grants) await loadGrants();
  }
  async function revoke(g: Grant) {
    const sure = await confirmChange({
      title: `Revoke ${g.name ?? "this credential"}?`, description: "Its access tokens stop working at once and its refresh token can no longer be used.", action: "Revoke",
    });
    if (!sure) return;
    if (await act(me, `Revoke ${g.name ?? shortId(g.id)}`, () => api(`/api/v1/grants/${g.id}`, { method: "DELETE" }))) await loadGrants();
  }

  return (
    <div className="rounded-lg border border-line bg-canvas">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
        <div>
          <h3 className="flex items-center gap-2 font-semibold text-strong"><Icon name="bot" />{m.display_name}</h3>
          <p className="font-mono text-xs text-muted">{shortId(m.user)}</p>
        </div>
        <div className="flex gap-2">
          <Badge className="border border-line">{m.role}</Badge>
          {!m.active ? <Badge color="warning">inactive</Badge> : null}
        </div>
      </header>
      <div className="space-y-4 p-4">
        <form className="flex flex-wrap items-end gap-2" aria-label={`Repository access of ${m.display_name}`} onSubmit={setRepoAccess}>
          <Select id={`sa-repo-${m.user}`} label="Repository" ariaLabel="Repository" value={accessRepo || null} onChange={setAccessRepo} items={repoItems}
            placeholder="No repositories" className="w-44" />
          <CheckboxGroup id={`sa-access-${m.user}`} legend="Access" items={ACCESS} value={access} onChange={setAccess} />
          <Button type="submit" size="sm" label="Set access" disabled={!repoItems.length} />
        </form>

        <form className="space-y-3 rounded-md border border-line p-3" aria-label={`Issue a credential to ${m.display_name}`} onSubmit={issueGrant}>
          <h4 className="text-sm font-medium text-strong">Issue a credential</h4>
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Name" htmlFor={`sa-gname-${m.user}`}>
              <Input id={`sa-gname-${m.user}`} value={grantName} onChange={(e) => setGrantName(e.target.value)} required maxLength={128} autoComplete="off"
                placeholder="ci-agent" className="w-40 max-w-full" />
            </Field>
            <Select id={`sa-grepo-${m.user}`} label="Repository" ariaLabel="Repository" value={grantRepo} onChange={setGrantRepo}
              items={[{ label: "Any it may use", value: ANY_REPO }, ...repoItems]} className="w-44" />
            <Select id={`sa-life-${m.user}`} label="Valid for" ariaLabel="Valid for" value={lifetime} onChange={setLifetime} items={LIFETIMES} className="w-32" />
          </div>
          <CheckboxGroup id={`sa-scope-${m.user}`} legend="Scopes" items={SCOPES} value={scope} onChange={setScope}
            error={scope.length ? undefined : "Choose at least one scope."} />
          <Button type="submit" size="sm" icon="key-round" label="Issue" disabled={!scope.length} />
        </form>

        <div className="space-y-2">
          <Button size="sm" color="neutral" variant="outline" aria-expanded={!!grants} label={grants ? "Hide credentials" : "Show credentials"} onClick={() => void toggleGrants()} />
          {grants ? (
            !grants.length ? <p className="text-sm text-muted">No credentials issued.</p> : (
              <Table caption={`Credentials of ${m.display_name}`}>
                <thead><tr><th>Name</th><th>Scope</th><th>Repository</th><th>Expires</th><th>Last used</th><th>Actions</th></tr></thead>
                <tbody>
                  {grants.map((g) => {
                    const iso = new Date(g.expires_ms).toISOString();
                    return (
                      <tr key={g.id}>
                        <td>
                          <span className="font-medium text-strong">{g.name ?? "—"}</span>
                          {g.revoked ? <Badge className="ms-1">revoked</Badge> : null}
                        </td>
                        <td>{g.scope}</td>
                        <td>{repoName(g.repo)}</td>
                        <td><time dateTime={iso}>{iso.slice(0, 10)}</time></td>
                        <td><RelTime ms={g.last_used_ms} /></td>
                        <td>
                          {!g.revoked ? (
                            <Button size="sm" color="error" variant="ghost" icon="ban" aria-label={`Revoke ${g.name ?? g.id}`} label="Revoke" onClick={() => void revoke(g)} />
                          ) : null}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </Table>
            )
          ) : null}
        </div>
      </div>
    </div>
  );
}
