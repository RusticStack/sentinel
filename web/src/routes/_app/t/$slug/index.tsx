import { useEffect, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import type { Pool, RunSummary } from "../../../../lib/types";
import { api, readCookie } from "../../../../lib/api.ts";
import { loadRepos } from "../../../../lib/repos.ts";
import { useLoaded } from "../../../../lib/hooks.ts";
import { CURSOR, DIGITS, HEX_PREFIX, NAME, NO_CONTROL, searchSchema } from "../../../../lib/search.ts";
import { shortId, shortRef, shortSha, words } from "../../../../lib/format.ts";
import { Page, rememberTenant } from "../../../../components/Page.tsx";
import { StateBadge } from "../../../../components/StateBadge.tsx";
import { RelTime } from "../../../../components/RelTime.tsx";
import { Button, ButtonLink, Empty, Field, Input, Select, Table, TextLink, useInterval } from "../../../../components/ui.tsx";

type Kind = "all" | "ref" | "pr" | "sha";
const KINDS = [{ label: "All runs", value: "all" }, { label: "Ref or branch", value: "ref" }, { label: "Pull request", value: "pr" }, { label: "Commit SHA", value: "sha" }];
interface RunPage { runs: RunSummary[]; next: string | null }

const repoCookie = (slug: string) => `sentinel-repo-${slug}`;

export const Route = createFileRoute("/_app/t/$slug/")({
  validateSearch: searchSchema({ repo: [NAME, 100], ref: [NO_CONTROL, 256], pr: [DIGITS, 10], sha: [HEX_PREFIX, 40], before: [CURSOR, 256] }),
  loaderDeps: ({ search }) => search,
  loader: async ({ params, deps }) => {
    const repos = await loadRepos(params.slug);
    const remembered = await readCookie(repoCookie(params.slug));
    const repo = deps.repo || (repos.repos.some((r) => r.name === remembered) ? remembered : repos.repos[0]?.name) || null;
    const [page, overview] = await Promise.all([
      repo ? readRuns(params.slug, repo, deps) : Promise.resolve({ runs: [], next: null } as RunPage),
      readOverview(params.slug),
    ]);
    return { repos, repo, page, overview };
  },
  head: ({ params }) => ({ meta: [{ title: `Runs · ${params.slug} · Sentinel` }] }),
  component: RunsView,
});

function query(deps: Record<string, string | undefined>) {
  const q = new URLSearchParams({ limit: "50" });
  for (const k of ["ref", "pr", "sha", "before"]) if (deps[k]) q.set(k, deps[k]!);
  return q.toString();
}
const readRuns = (slug: string, repo: string, deps: Record<string, string | undefined>) =>
  api<RunPage>(`/api/v1/tenants/${encodeURIComponent(slug)}/repos/${encodeURIComponent(repo)}/runs?${query(deps)}`);

// What the controller reports about the tenant right now; nothing here is estimated.
interface Overview { waiting: number | null; workers: number | null; connected: number | null; held: number | null }
async function readOverview(slug: string): Promise<Overview> {
  const t = encodeURIComponent(slug);
  const [queue, workers] = await Promise.all([
    api<{ total: number }>(`/api/v1/queue?tenant=${t}&limit=1`).catch(() => null),
    api<{ pools: Pool[] }>(`/api/v1/workers?tenant=${t}`).catch(() => null),
  ]);
  const all = workers ? [...new Map(workers.pools.flatMap((p) => p.workers).map((w) => [w.id, w])).values()] : null;
  return {
    waiting: queue?.total ?? null,
    workers: all ? all.length : null,
    connected: all ? all.filter((w) => w.connected).length : null,
    held: all ? all.reduce((n, w) => n + w.held_attempts, 0) : null,
  };
}

function Stat({ label, value, to, note }: { label: string; value: string; to?: string; note?: string }) {
  return (
    <div className="rounded-lg border border-line bg-canvas px-4 py-3">
      <dt className="text-xs font-medium uppercase tracking-wide text-muted">{to ? <TextLink to={to}>{label}</TextLink> : label}</dt>
      <dd className="mt-1 text-2xl font-semibold text-strong">{value}</dd>
      {note ? <dd className="text-xs text-muted">{note}</dd> : null}
    </div>
  );
}

function RunsView() {
  const { slug } = Route.useParams();
  const search = Route.useSearch();
  const loaded = Route.useLoaderData();
  const navigate = useNavigate();
  const [page, setPage] = useLoaded<RunPage>(loaded.page);
  const [overview, setOverview] = useLoaded<Overview>(loaded.overview);
  const [kind, setKind] = useState<Kind>(search.ref ? "ref" : search.pr ? "pr" : search.sha ? "sha" : "all");
  const [value, setValue] = useState(search.ref || search.pr || search.sha || "");
  const [repoPick, setRepoPick] = useState<string | null>(loaded.repo);

  useEffect(() => { rememberTenant(slug); }, [slug]);
  useEffect(() => {
    setKind(search.ref ? "ref" : search.pr ? "pr" : search.sha ? "sha" : "all");
    setValue(search.ref || search.pr || search.sha || "");
    setRepoPick(loaded.repo);
  }, [search.ref, search.pr, search.sha, loaded.repo]);
  // The first page refreshes every 10 s; an older page stays as it was read.
  useInterval(() => {
    if (!search.before && loaded.repo) readRuns(slug, loaded.repo, search).then(setPage, () => {});
    readOverview(slug).then(setOverview, () => {});
  }, 10000);

  function apply(e: React.FormEvent) {
    e.preventDefault();
    const q: Record<string, string> = { repo: repoPick || "" };
    if (kind !== "all" && value.trim()) q[kind] = value.trim();
    if (repoPick) document.cookie = `${repoCookie(slug)}=${encodeURIComponent(repoPick)}; Path=/; Max-Age=${60 * 60 * 24 * 365}; SameSite=Lax${location.protocol === "https:" ? "; Secure" : ""}`;
    void navigate({ to: "/t/$slug", params: { slug }, search: q as never });
  }

  if (!loaded.repos.repos.length) {
    return (
      <Page id="runs" title={`Runs · ${slug}`}>
        <Empty icon="folder-git-2" title="No repositories" description="There are no repositories you can read in this tenant." />
      </Page>
    );
  }

  return (
    <Page id="runs" title={`Runs · ${slug}`}>
      <section aria-label="Overview">
        <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat label="Repositories" value={String(loaded.repos.repos.length)} />
          <Stat label="Waiting jobs" to={`/t/${slug}/queue`} value={overview.waiting === null ? "—" : String(overview.waiting)} />
          <Stat label="Workers connected" to={`/t/${slug}/workers`} value={overview.connected === null ? "—" : `${overview.connected} of ${overview.workers}`} />
          <Stat label="Attempts held" value={overview.held === null ? "—" : String(overview.held)} note="on the workers this tenant may use" />
        </dl>
      </section>
      <form className="flex flex-wrap items-end gap-3" role="search" aria-label="Filter runs" onSubmit={apply}>
        <Select id="f-repo" label="Repository" className="w-44" value={repoPick} onChange={setRepoPick}
          items={loaded.repos.repos.map((r) => ({ label: r.name, value: r.name }))} />
        <Select id="f-kind" label="Filter" className="w-40" value={kind} onChange={(v) => setKind(v as Kind)} items={KINDS} />
        <Field label="Value" htmlFor="f-value">
          <Input id="f-value" className="w-56" value={value} onChange={(e) => setValue(e.target.value)} disabled={kind === "all"} placeholder="main, 42 or a SHA prefix" />
        </Field>
        <Button type="submit" icon="search" label="Show runs" />
      </form>

      <Table caption={`Runs of ${loaded.repo}`}>
        <thead><tr><th>Run</th><th>State</th><th>Trigger</th><th>Ref</th><th>PR</th><th>Commit</th><th>Created</th></tr></thead>
        <tbody>
          {page.runs.length ? page.runs.map((r) => (
            <tr key={r.id}>
              <td><TextLink to={`/runs/${r.id}`} className="font-medium">{shortId(r.id)}</TextLink></td>
              <td><StateBadge state={r.state} /></td>
              <td>{words(r.trigger)}</td>
              <td><code className="text-xs">{shortRef(r.ref)}</code></td>
              <td>{r.pr ? `#${r.pr}` : "—"}</td>
              <td><code className="text-xs">{shortSha(r.sha)}</code></td>
              <td><RelTime ms={r.created_ms} /></td>
            </tr>
          )) : <tr><td colSpan={7} className="text-center text-muted">No runs match.</td></tr>}
        </tbody>
      </Table>
      <div className="flex gap-2">
        {search.before ? <ButtonLink to={`/t/${slug}`} search={{ ...search, before: undefined }} color="neutral" variant="outline" icon="arrow-up-to-line" label="Newest" /> : null}
        {page.next ? (
          <ButtonLink to={`/t/${slug}`} search={{ ...search, repo: loaded.repo ?? undefined, before: page.next }} color="neutral" variant="outline" label={<>Older runs <span aria-hidden="true">→</span></>} />
        ) : null}
      </div>
    </Page>
  );
}
