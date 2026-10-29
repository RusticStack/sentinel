import { useState } from "react";
import { api } from "../../lib/api.ts";
import { act } from "../../lib/act.tsx";
import { useSession } from "../../lib/session.ts";
import { useOverride } from "../../lib/override.ts";
import { attempt, useLoad, type Load } from "../../lib/loaded.ts";
import { loadRepos, type RepoList } from "../../lib/repos.ts";
import { LoadFailed } from "../LoadFailed.tsx";
import { Button, Card, Field, Icon, Input } from "../ui.tsx";
import { CheckboxGroup } from "./CheckboxGroup.tsx";

interface Source { bound: boolean; remote?: string; allowed_refs?: string[]; pipeline_path?: string; trust_pinned?: boolean; version?: number; revoked?: boolean }
const ACCESS = [{ label: "Read", value: "read" }, { label: "Run", value: "run" }, { label: "Secrets", value: "secrets" }];
export const loadRepoList = (slug: string) => attempt(() => loadRepos(slug));

export function Repos({ slug, initial }: { slug: string; initial: Load<RepoList> }) {
  const { me } = useSession();
  const { data, setData, failure } = useLoad(initial);
  const refresh = () => loadRepos(slug).then(setData, () => {});
  const [name, setName] = useState("");
  const base = `/api/v1/tenants/${encodeURIComponent(slug)}/repos`;

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (await act(me, `Create ${name}`, () => api(base, { method: "POST", body: { name } }))) {
      setName("");
      await refresh();
    }
  }

  return (
    <>
      <section aria-labelledby="repos-h" className="space-y-3">
        <h2 id="repos-h" className="text-base font-semibold text-strong">Repositories</h2>
        <p className="text-sm text-muted">Source bindings, deploy credentials and hook secrets are set on the controller host (<code>sentinel admin source …</code>); credentials never cross the API.</p>
        {failure ? <LoadFailed what="the repositories" words={failure} /> : (
          <div className="grid gap-3 md:grid-cols-2">
            {(data?.repos ?? []).map((repo) => <RepoCard key={repo.id} slug={slug} repo={repo} />)}
          </div>
        )}
      </section>
      <section aria-labelledby="new-repo-h" className="space-y-3">
        <h2 id="new-repo-h" className="text-base font-semibold text-strong">Add a repository</h2>
        <form className="flex flex-wrap items-end gap-3" aria-label="Add a repository" onSubmit={create}>
          <Field label="Name" htmlFor="r-name">
            <Input id="r-name" name="name" value={name} onChange={(e) => setName(e.target.value)} required pattern="[A-Za-z0-9._\-]{1,128}" className="w-56 max-w-full" />
          </Field>
          <Button type="submit" icon="plus" label="Create" />
        </form>
      </section>
    </>
  );
}

function RepoCard({ slug, repo }: { slug: string; repo: { id: string; name: string } }) {
  const { me } = useSession();
  const { ready, withReason } = useOverride(slug);
  const [source, setSource] = useState<Source | null>(null);
  const [who, setWho] = useState("");
  const [access, setAccess] = useState<string[]>(["read"]);
  const base = `/api/v1/tenants/${encodeURIComponent(slug)}/repos/${encodeURIComponent(repo.name)}`;

  async function toggleSource() {
    if (source) { setSource(null); return; }
    const s = await act(me, `Source of ${repo.name}`, () => api<Source>(`${base}/source`), false);
    if (s) setSource(s);
  }
  async function grant(e: React.FormEvent) {
    e.preventDefault();
    if (!ready()) return;
    await act(me, `Access to ${repo.name}`, () => api(`${base}/grants/${encodeURIComponent(who)}`, { method: "PUT", body: withReason({ access }) }));
  }

  return (
    <Card>
      <div className="space-y-3">
        <div className="flex items-center justify-between gap-2">
          <h3 className="flex min-w-0 items-center gap-2 font-semibold text-strong"><Icon name="folder-git-2" /><span className="truncate">{repo.name}</span></h3>
          <Button size="sm" color="neutral" variant="outline" aria-expanded={!!source} label="Source binding" onClick={() => void toggleSource()} />
        </div>
        {source?.bound ? (
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted">Remote</dt><dd><code className="break-all text-xs">{source.remote}</code></dd>
            <dt className="text-muted">Allowed refs</dt><dd><code className="text-xs">{(source.allowed_refs ?? []).join(", ") || "—"}</code></dd>
            <dt className="text-muted">Pipeline</dt><dd><code className="text-xs">{source.pipeline_path}</code></dd>
            <dt className="text-muted">Trust pinned</dt><dd>{source.trust_pinned ? "yes" : "no"}</dd>
            <dt className="text-muted">Version</dt><dd>{source.version}{source.revoked ? " (revoked)" : null}</dd>
          </dl>
        ) : source ? <p className="text-sm text-muted">No source binding yet.</p> : null}
        <form className="flex flex-wrap items-end gap-2" aria-label={`Grant access to ${repo.name}`} onSubmit={grant}>
          <Field label="Member" htmlFor={`g-${repo.id}`}>
            <Input id={`g-${repo.id}`} value={who} onChange={(e) => setWho(e.target.value)} required className="w-40 max-w-full" />
          </Field>
          <CheckboxGroup id={`a-${repo.id}`} legend="Access" items={ACCESS} value={access} onChange={setAccess} />
          <Button type="submit" size="sm" label="Set access" />
        </form>
      </div>
    </Card>
  );
}
