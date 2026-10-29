import { useState } from "react";
import type { Member, NamespaceSettings } from "../../lib/types";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { refreshTenants, useSession } from "../../lib/session.ts";
import { useOverride } from "../../lib/override.ts";
import { attempt, useLoad, type Load } from "../../lib/loaded.ts";
import { shortId } from "../../lib/format.ts";
import { Alert, Badge, Button, ButtonLink, Field, Input, Select, Table, TextLink } from "../ui.tsx";
import { LoadFailed } from "../LoadFailed.tsx";
import { confirmChange } from "./Confirm.tsx";

export interface MembersPage { members: Member[]; next: string | null }
const ROLES = [{ label: "Reader", value: "reader" }, { label: "Operator", value: "operator" }, { label: "Admin", value: "admin" }];
const readMembers = (slug: string) => api<MembersPage>(`/api/v1/tenants/${encodeURIComponent(slug)}/members?limit=100`);
export const loadMembers = (slug: string) => attempt(() => readMembers(slug));
const nameOf = (m: Member) => m.username || m.display_name;

export function Members({ slug, settings, initial }: { slug: string; settings: NamespaceSettings | null; initial: Load<MembersPage> }) {
  const { me } = useSession();
  const { ready, withReason } = useOverride(slug);
  const { data, setData, failure } = useLoad(initial);
  const refresh = () => readMembers(slug).then(setData, () => {});
  const githubManaged = settings?.membership === "github";
  const personal = settings?.kind === "personal";
  const [who, setWho] = useState("");
  const [role, setRole] = useState("reader");
  const base = `/api/v1/tenants/${encodeURIComponent(slug)}/members`;

  async function changeRole(m: Member, next: string) {
    if (!ready()) return;
    const done = await act(me, `Role of ${nameOf(m)}`, () => api(`${base}/${m.user}`, { method: "PUT", body: withReason({ role: next }) }));
    await refresh();
    if (done) await refreshTenants();
  }
  async function add(e: React.FormEvent) {
    e.preventDefault();
    if (!ready()) return;
    if (await act(me, `Add ${who}`, () => api(`${base}/${encodeURIComponent(who)}`, { method: "PUT", body: withReason({ role }) }))) {
      setWho("");
      await refresh();
    }
  }
  async function remove(m: Member) {
    const sure = await confirmChange({
      title: `Remove ${nameOf(m)}?`, description: "Their credentials for this tenant are revoked at once, and open pages lose access.", action: "Remove",
    });
    if (!sure) return;
    if (await act(me, `Remove ${nameOf(m)}`, () => api(`${base}/${m.user}`, { method: "DELETE" }))) {
      await refresh();
      await refreshTenants();
    }
  }

  const members = data?.members ?? [];
  return (
    <>
      <section aria-labelledby="members-h" className="space-y-3">
        <h2 id="members-h" className="text-base font-semibold text-strong">Members</h2>
        {failure ? <LoadFailed what="the members" words={failure} /> : <Table caption="Members">
          <thead><tr><th>Member</th><th>Kind</th><th>Role</th><th>Actions</th></tr></thead>
          <tbody>
            {members.length ? members.map((m) => (
              <tr key={m.user}>
                <td>
                  <div className="font-medium text-strong">{nameOf(m)}</div>
                  <div className="font-mono text-xs text-muted">{shortId(m.user)}</div>
                  {!m.active ? <Badge color="warning">inactive</Badge> : null}
                  {m.source === "github" ? <Badge>from GitHub</Badge> : null}
                </td>
                <td>{m.kind}</td>
                <td>
                  <Select ariaLabel={`Role of ${nameOf(m)}`} value={m.role} className="w-36" isDisabled={m.source === "github"}
                    items={m.kind === "service" ? ROLES.filter((r) => r.value !== "admin") : ROLES}
                    onChange={(v) => { if (v !== m.role) void changeRole(m, v); }} />
                </td>
                <td>
                  {m.source !== "github" ? (
                    <Button size="sm" color="error" variant="ghost" icon="user-minus" aria-label={`Remove ${nameOf(m)}`} onClick={() => void remove(m)}>Remove</Button>
                  ) : <span className="text-xs text-muted">Managed on GitHub</span>}
                </td>
              </tr>
            )) : <tr><td colSpan={4} className="text-center text-muted">No data</td></tr>}
          </tbody>
        </Table>}
        {data?.next ? <p className="text-sm text-muted">Only the first 100 members are shown.</p> : null}
      </section>

      {githubManaged ? (
        <Alert color="neutral" icon="github" title="Membership of this organization is managed by GitHub."
          description="People join and leave on GitHub, and Sentinel follows: owners are administrators here, other members operators. Members from GitHub cannot be changed or removed here; service accounts are still managed here (Service accounts)." />
      ) : personal ? (
        <Alert color="neutral" icon="user" title="A personal namespace has no other members." description="Create an organization to work with others.">
          <div className="pt-1"><ButtonLink to="/organizations" size="sm" color="neutral" variant="outline" label="Organizations" /></div>
        </Alert>
      ) : (
        <section aria-labelledby="add-h" className="space-y-3">
          <h2 id="add-h" className="text-base font-semibold text-strong">Add a member</h2>
          {settings?.kind === "organization" && !settings.github_installation
            ? <p className="text-sm text-muted">To add someone who has no account yet, <TextLink to={`/t/${slug}/admin/invitations`}>invite them by email</TextLink>.</p>
            : null}
          <form className="flex flex-wrap items-end gap-3" aria-label="Add a member" onSubmit={add}>
            <Field label="Username or user id" htmlFor="m-user">
              <Input id="m-user" name="who" value={who} onChange={(e) => setWho(e.target.value)} required autoComplete="off" className="w-56 max-w-full" />
            </Field>
            <Select id="m-role" label="Role" ariaLabel="Role" value={role} onChange={setRole} items={ROLES} className="w-36" />
            <Button type="submit" icon="user-plus" label="Add or change" />
          </form>
        </section>
      )}
    </>
  );
}
