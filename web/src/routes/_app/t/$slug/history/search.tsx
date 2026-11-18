import { useEffect, useRef, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { api, readCookie } from "../../../../../lib/api.ts";
import { refusal } from "../../../../../lib/act.tsx";
import { ApiError } from "../../../../../lib/api.ts";
import { announce } from "../../../../../lib/announce.tsx";
import { attempt, type Load } from "../../../../../lib/loaded.ts";
import { useLoaded } from "../../../../../lib/hooks.ts";
import { loadRepos } from "../../../../../lib/repos.ts";
import { DIGITS, NAME, NO_CONTROL, searchSchema } from "../../../../../lib/search.ts";
import { fmtBytes, shortId } from "../../../../../lib/format.ts";
import { SEARCH_WINDOWS, addPage, searchPath, searchWords, splitHit, type LogSearch } from "../../../../../lib/history.ts";
import { Page, rememberTenant } from "../../../../../components/Page.tsx";
import { LoadFailed } from "../../../../../components/LoadFailed.tsx";
import { HistoryNav } from "../../../../../components/history/HistoryNav.tsx";
import { Alert, Button, Empty, Field, Input, Select, Table, TextLink } from "../../../../../components/ui.tsx";

const repoCookie = (slug: string) => `sentinel-repo-${slug}`;

// The router passes on the parameters it could not validate too; the loader reads only the validated ones.
const schema = searchSchema({ repo: [NAME, 100], runs: [DIGITS, 3], q: [NO_CONTROL, 256] });

export const Route = createFileRoute("/_app/t/$slug/history/search")({
  validateSearch: schema,
  loaderDeps: ({ search }) => schema["~standard"].validate(search).value,
  loader: async ({ params, deps }) => {
    const repos = await loadRepos(params.slug);
    const remembered = await readCookie(repoCookie(params.slug));
    const repo = deps.repo || (repos.repos.some((r) => r.name === remembered) ? remembered : repos.repos[0]?.name) || null;
    const found: Load<LogSearch> | null = repo && deps.q
      ? await attempt(() => api<LogSearch>(searchPath(params.slug, repo, deps.q!, deps.runs)))
      : null;
    return { repos, repo, found };
  },
  head: ({ params }) => ({ meta: [{ title: `Log search · ${params.slug} · Sentinel` }] }),
  component: SearchView,
});

function SearchView() {
  const { slug } = Route.useParams();
  const search = Route.useSearch();
  const loaded = Route.useLoaderData();
  const navigate = useNavigate();
  const [state, setState] = useLoaded<Load<LogSearch>>(loaded.found ?? { value: null, failure: null });
  const [repoPick, setRepoPick] = useState<string | null>(loaded.repo);
  const [term, setTerm] = useState(search.q ?? "");
  const [runs, setRuns] = useState(search.runs && SEARCH_WINDOWS.includes(search.runs) ? search.runs : "20");
  const [more, setMore] = useState<{ busy: boolean; failure: string | null }>({ busy: false, failure: null });
  const generation = useRef(0);

  useEffect(() => { rememberTenant(slug); }, [slug]);
  useEffect(() => { setRepoPick(loaded.repo); setTerm(search.q ?? ""); generation.current++; setMore({ busy: false, failure: null }); }, [loaded.repo, search.q]);
  useEffect(() => { setRuns(search.runs && SEARCH_WINDOWS.includes(search.runs) ? search.runs : "20"); }, [search.runs]);

  const found = state.value;
  const repo = loaded.repo;
  const queried = search.q ?? "";

  function apply(e: React.FormEvent) {
    e.preventDefault();
    if (!term) return;
    void navigate({ to: "/t/$slug/history/search", params: { slug }, search: { repo: repoPick || "", runs, q: term } as never });
  }

  // The next page of the same search, from the position the last answer named; the window is counted down by the controller.
  async function continueSearch() {
    if (!found?.next || !repo || more.busy) return;
    const mine = generation.current;
    setMore({ busy: true, failure: null });
    try {
      const page = await api<LogSearch>(searchPath(slug, repo, queried, search.runs, found.next));
      if (mine !== generation.current) return;
      const merged = addPage(found, page);
      setState({ value: merged, failure: null });
      setMore({ busy: false, failure: null });
      announce(`${page.matches.length} more ${page.matches.length === 1 ? "line" : "lines"} found.`);
    } catch (e) {
      if (mine !== generation.current) return;
      setMore({ busy: false, failure: refusal(e instanceof ApiError ? e : new ApiError(0, null)) });
    }
  }

  const nav = <HistoryNav slug={slug} repo={repo} current="search" />;
  if (!loaded.repos.repos.length || !repo) {
    return (
      <Page id="history-search" title={`Log search · ${slug}`}>
        {nav}
        <Empty icon="folder-git-2" title="No repositories" description="There are no repositories you can read in this tenant." />
      </Page>
    );
  }

  return (
    <Page id="history-search" title={`Log search · ${slug}`}>
      {nav}
      <form className="flex flex-wrap items-end gap-3" role="search" aria-label="Search the logs of recent runs" onSubmit={apply}>
        <Select id="s-repo" label="Repository" className="w-44" value={repoPick} onChange={setRepoPick}
          items={loaded.repos.repos.map((r) => ({ label: r.name, value: r.name }))} />
        <Select id="s-runs" label="Runs" className="w-32" value={runs} onChange={setRuns}
          items={SEARCH_WINDOWS.map((n) => ({ label: `Last ${n}`, value: n }))} />
        <Field label="Text" htmlFor="s-term" hint="Matched exactly, up to 256 bytes">
          <Input id="s-term" className="w-72" value={term} maxLength={256} onChange={(e) => setTerm(e.target.value)} placeholder="an error message" autoComplete="off" />
        </Field>
        <Button type="submit" icon="search" label="Search logs" disabled={!term} />
      </form>

      {state.failure && !found ? <LoadFailed what="the search" words={state.failure} /> : null}
      {found ? (
        <section aria-labelledby="results-h" className="space-y-3">
          <h2 id="results-h" className="text-base font-semibold text-strong">
            {found.matches.length} {found.matches.length === 1 ? "line" : "lines"} found for <code className="text-sm">{queried}</code>
          </h2>
          <p className="text-sm text-muted" role="status">{searchWords(found, fmtBytes)}</p>
          {found.expired_attempts ? <Alert color="warning" icon="archive-x" role="status" description="Retention removed some of these logs, so lines in them cannot be found." /> : null}
          <Table caption={`Lines matching ${queried} in the recent runs of ${repo}`}>
            <thead><tr><th>Run</th><th>Job</th><th>Where</th><th>Line</th></tr></thead>
            <tbody>
              {found.matches.length ? found.matches.map((m, i) => {
                const [before, hit, after] = splitHit(m.text, queried);
                return (
                  <tr key={`${m.attempt}:${m.seq}:${i}`}>
                    <td><TextLink to={`/runs/${m.run}`} className="font-medium">{shortId(m.run)}</TextLink></td>
                    <td>{m.job}</td>
                    <td className="whitespace-nowrap">
                      <TextLink to={`/runs/${m.run}/logs/${m.attempt}`} search={{ step: String(m.step), seq: String(m.seq), q: queried }}>step {m.step}, chunk {m.seq}</TextLink>
                      <span className="text-muted"> · {m.stream}</span>
                    </td>
                    <td><code className="break-all text-xs">{before}{hit ? <mark className="rounded-sm bg-warning/30 px-0.5 text-strong">{hit}</mark> : null}{after}</code></td>
                  </tr>
                );
              }) : <tr><td colSpan={4} className="text-center text-muted">No line matches{found.complete ? "." : " yet."}</td></tr>}
            </tbody>
          </Table>
          {found.next ? (
            <div className="flex flex-wrap items-center gap-3">
              <Button color="neutral" variant="outline" icon="history" label="Search further back" loading={more.busy} onClick={() => { void continueSearch(); }} />
              <span className="text-sm text-muted">Each step reads at most 4 MiB of log.</span>
            </div>
          ) : null}
          {more.failure ? <Alert color="error" icon="circle-alert" role="alert" title="Could not continue the search." description={more.failure} /> : null}
        </section>
      ) : !state.failure ? (
        <p className="text-sm text-muted">Search the logs of a repository's recent runs for exact text. Each request reads at most 4 MiB, and you can keep going until the window is covered.</p>
      ) : null}
    </Page>
  );
}
