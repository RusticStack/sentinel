import { useEffect, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { api, readCookie } from "../../../../../lib/api.ts";
import { attempt, useLoad, type Load } from "../../../../../lib/loaded.ts";
import { loadRepos } from "../../../../../lib/repos.ts";
import { DIGITS, NAME, NO_CONTROL, searchSchema } from "../../../../../lib/search.ts";
import { fmtNs, shortId } from "../../../../../lib/format.ts";
import { DURATION_WINDOWS, TABLE_PHASES, defaultPair, durationsPath, windowWords, type Durations, type Percentiles } from "../../../../../lib/history.ts";
import { Page, rememberTenant } from "../../../../../components/Page.tsx";
import { RelTime } from "../../../../../components/RelTime.tsx";
import { LoadFailed } from "../../../../../components/LoadFailed.tsx";
import { HistoryNav } from "../../../../../components/history/HistoryNav.tsx";
import { Alert, Button, ButtonLink, Empty, Select, Table, TextLink } from "../../../../../components/ui.tsx";

// The repository the runs view remembered is the one history opens on.
const repoCookie = (slug: string) => `sentinel-repo-${slug}`;

// The router passes on the parameters it could not validate too; the loader reads only the validated ones.
const schema = searchSchema({ repo: [NAME, 100], runs: [DIGITS, 3], job: [NO_CONTROL, 128] });

export const Route = createFileRoute("/_app/t/$slug/history/")({
  validateSearch: schema,
  loaderDeps: ({ search }) => schema["~standard"].validate(search).value,
  loader: async ({ params, deps }) => {
    const repos = await loadRepos(params.slug);
    const remembered = await readCookie(repoCookie(params.slug));
    const repo = deps.repo || (repos.repos.some((r) => r.name === remembered) ? remembered : repos.repos[0]?.name) || null;
    const durations: Load<Durations> | null = repo
      ? await attempt(() => api<Durations>(durationsPath(params.slug, repo, deps.runs, deps.job)))
      : null;
    return { repos, repo, durations };
  },
  head: ({ params }) => ({ meta: [{ title: `History · ${params.slug} · Sentinel` }] }),
  component: HistoryView,
});

const both = (p: Percentiles | null | undefined) => (p ? `${fmtNs(p.p50_ns)} / ${fmtNs(p.p95_ns)}` : "—");

function HistoryView() {
  const { slug } = Route.useParams();
  const search = Route.useSearch();
  const loaded = Route.useLoaderData();
  const navigate = useNavigate();
  const { data, failure } = useLoad<Durations>(loaded.durations ?? { value: null, failure: null });
  const [repoPick, setRepoPick] = useState<string | null>(loaded.repo);
  const [runs, setRuns] = useState(search.runs && DURATION_WINDOWS.includes(search.runs) ? search.runs : "100");
  const job = search.job ?? null;
  const samples = job ? data?.jobs.find((j) => j.job === job)?.samples : undefined;
  const pair = defaultPair(samples);
  const [base, setBase] = useState<string | null>(pair.base);
  const [head, setHead] = useState<string | null>(pair.head);

  useEffect(() => { rememberTenant(slug); }, [slug]);
  useEffect(() => { setRepoPick(loaded.repo); }, [loaded.repo]);
  useEffect(() => { setRuns(search.runs && DURATION_WINDOWS.includes(search.runs) ? search.runs : "100"); }, [search.runs]);
  useEffect(() => { setBase(pair.base); setHead(pair.head); }, [pair.base, pair.head]);

  function apply(e: React.FormEvent) {
    e.preventDefault();
    const q: Record<string, string> = { repo: repoPick || "", runs };
    void navigate({ to: "/t/$slug/history", params: { slug }, search: q as never });
  }

  const nav = <HistoryNav slug={slug} repo={loaded.repo} current="durations" />;
  if (!loaded.repos.repos.length || !loaded.repo) {
    return (
      <Page id="history" title={`History · ${slug}`}>
        {nav}
        <Empty icon="folder-git-2" title="No repositories" description="There are no repositories you can read in this tenant." />
      </Page>
    );
  }

  return (
    <Page id="history" title={`History · ${slug}`}>
      {nav}
      <form className="flex flex-wrap items-end gap-3" role="search" aria-label="Choose the history window" onSubmit={apply}>
        <Select id="h-repo" label="Repository" className="w-44" value={repoPick} onChange={setRepoPick}
          items={loaded.repos.repos.map((r) => ({ label: r.name, value: r.name }))} />
        <Select id="h-runs" label="Runs" className="w-32" value={runs} onChange={setRuns}
          items={DURATION_WINDOWS.map((n) => ({ label: `Last ${n}`, value: n }))} />
        <Button type="submit" icon="search" label="Show durations" />
      </form>

      {failure ? <LoadFailed what="job durations" words={failure} /> : data ? (
        <>
          <section aria-labelledby="durations-h" className="space-y-3">
            <h2 id="durations-h" className="text-base font-semibold text-strong">Job durations in {loaded.repo}</h2>
            <p className="text-sm text-muted" id="window-note">
              {windowWords(data.window)}{" "}
              {data.window.runs ? <>From <RelTime ms={data.window.oldest_ms} /> to <RelTime ms={data.window.newest_ms} />. </> : null}
              Each run counts the newest attempt of each job. A duration is the longer of checkout and image pull, then container start, steps and finalize, and is shown only for attempts that measured all of them.
            </p>
            {data.truncated ? <Alert color="warning" icon="info" role="status" description="Only the first 128 job names are shown; the window has more." /> : null}
            {data.unreadable ? <Alert color="warning" icon="info" role="status" description={`${data.unreadable} stored summaries could not be read and are left out.`} /> : null}
            <Table caption={`Duration percentiles per job of ${loaded.repo}`}>
              <thead>
                <tr>
                  <th>Job</th><th>Attempts</th><th>Duration p50 / p95</th>
                  {TABLE_PHASES.map((p) => <th key={p.key}>{p.label} p50 / p95</th>)}
                </tr>
              </thead>
              <tbody>
                {data.jobs.length ? data.jobs.map((j) => (
                  <tr key={j.job}>
                    <td>
                      <TextLink to={`/t/${slug}/history`} search={{ repo: loaded.repo!, runs: search.runs, job: j.job }} className="font-medium">{j.job}</TextLink>
                    </td>
                    <td>{j.attempts}</td>
                    <td title={j.total ? `over ${j.total.count} attempts` : "no attempt measured every phase"}>{both(j.total)}</td>
                    {TABLE_PHASES.map((p) => <td key={p.key} title={j.phases[p.key] ? `over ${j.phases[p.key]!.count} attempts` : "not measured"}>{both(j.phases[p.key])}</td>)}
                  </tr>
                )) : <tr><td colSpan={3 + TABLE_PHASES.length} className="text-center text-muted">No finished attempts in this window.</td></tr>}
              </tbody>
            </Table>
          </section>

          {job ? (
            <section aria-labelledby="samples-h" className="space-y-3">
              <h2 id="samples-h" className="text-base font-semibold text-strong">Runs of {job}</h2>
              {samples?.length ? (
                <>
                  <p className="text-sm text-muted">Choose two attempts to compare their phases. The newest is the head and the one before it the base.</p>
                  <Table caption={`Attempts of ${job}, newest first`}>
                    <thead><tr><th>Base</th><th>Head</th><th>Run</th><th>Attempt</th><th>Created</th><th>Duration</th>{TABLE_PHASES.map((p) => <th key={p.key}>{p.label}</th>)}</tr></thead>
                    <tbody>
                      {samples.map((s) => (
                        <tr key={s.attempt}>
                          <td><input type="radio" name="base" className="size-4" checked={base === s.attempt} onChange={() => setBase(s.attempt)} aria-label={`Use the attempt of run ${shortId(s.run)} as base`} /></td>
                          <td><input type="radio" name="head" className="size-4" checked={head === s.attempt} onChange={() => setHead(s.attempt)} aria-label={`Use the attempt of run ${shortId(s.run)} as head`} /></td>
                          <td><TextLink to={`/runs/${s.run}`} className="font-medium">{shortId(s.run)}</TextLink></td>
                          <td><TextLink to={`/runs/${s.run}/logs/${s.attempt}`}>{s.fence > 1 ? `attempt ${s.fence}` : "log"}</TextLink></td>
                          <td><RelTime ms={s.created_ms} /></td>
                          <td>{fmtNs(s.total_ns)}</td>
                          {TABLE_PHASES.map((p) => <td key={p.key}>{fmtNs(s.timings_ns[p.key])}</td>)}
                        </tr>
                      ))}
                    </tbody>
                  </Table>
                  <div className="flex flex-wrap items-center gap-3">
                    {base && head && base !== head ? (
                      <ButtonLink to={`/t/${slug}/history/compare`} search={{ repo: loaded.repo!, base, head }} icon="git-merge" label="Compare phases" />
                    ) : (
                      <Button icon="git-merge" label="Compare phases" disabled />
                    )}
                    {base && head && base === head ? <span className="text-sm text-muted">Choose two different attempts.</span> : null}
                  </div>
                </>
              ) : (
                <Empty title="No finished attempts" description={`No run in this window has a finished attempt of ${job}.`} headingLevel={3} />
              )}
            </section>
          ) : <p className="text-sm text-muted">Choose a job to list its recent runs and compare two of them.</p>}
        </>
      ) : null}
    </Page>
  );
}
