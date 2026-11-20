import { useEffect, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { api, readCookie } from "../../../../../lib/api.ts";
import { attempt, type Load } from "../../../../../lib/loaded.ts";
import { loadRepos } from "../../../../../lib/repos.ts";
import { DIGITS, NAME, searchSchema } from "../../../../../lib/search.ts";
import { fmtRate, flakesPath, FLAKE_WINDOWS, type Flakes } from "../../../../../lib/history.ts";
import { Page, rememberTenant } from "../../../../../components/Page.tsx";
import { RelTime } from "../../../../../components/RelTime.tsx";
import { LoadFailed } from "../../../../../components/LoadFailed.tsx";
import { HistoryNav } from "../../../../../components/history/HistoryNav.tsx";
import { Alert, Button, Empty, Select, Table } from "../../../../../components/ui.tsx";

// The repository the runs view remembered is the one the flaky list opens on.
const repoCookie = (slug: string) => `sentinel-repo-${slug}`;

// The router passes on the parameters it could not validate too; the loader reads only the validated ones.
const schema = searchSchema({ repo: [NAME, 100], days: [DIGITS, 3] });

export const Route = createFileRoute("/_app/t/$slug/history/flakes")({
  validateSearch: schema,
  loaderDeps: ({ search }) => schema["~standard"].validate(search).value,
  loader: async ({ params, deps }) => {
    const repos = await loadRepos(params.slug);
    const remembered = await readCookie(repoCookie(params.slug));
    const repo = deps.repo || (repos.repos.some((r) => r.name === remembered) ? remembered : repos.repos[0]?.name) || null;
    const flakes: Load<Flakes> | null = repo
      ? await attempt(() => api<Flakes>(flakesPath(params.slug, repo, deps.days)))
      : null;
    return { repos, repo, flakes };
  },
  head: ({ params }) => ({ meta: [{ title: `Flaky tests · ${params.slug} · Sentinel` }] }),
  component: FlakesView,
});

function FlakesView() {
  const { slug } = Route.useParams();
  const search = Route.useSearch();
  const loaded = Route.useLoaderData();
  const navigate = useNavigate();
  const text = search.days && FLAKE_WINDOWS.includes(search.days) ? search.days : "14";
  const [repoPick, setRepoPick] = useState<string | null>(loaded.repo);
  const [days, setDays] = useState(text);

  useEffect(() => { rememberTenant(slug); }, [slug]);
  useEffect(() => { setRepoPick(loaded.repo); }, [loaded.repo]);
  useEffect(() => { setDays(search.days && FLAKE_WINDOWS.includes(search.days) ? search.days : "14"); }, [search.days]);

  function apply(e: React.FormEvent) {
    e.preventDefault();
    void navigate({ to: "/t/$slug/history/flakes", params: { slug }, search: { repo: repoPick || "", days } as never });
  }

  const nav = <HistoryNav slug={slug} repo={loaded.repo} current="flakes" />;
  const data = loaded.flakes?.value ?? null;
  const failure = loaded.flakes?.failure ?? null;

  if (!loaded.repos.repos.length || !loaded.repo) {
    return (
      <Page id="flaky-tests" title={`Flaky tests · ${slug}`}>
        {nav}
        <Empty icon="folder-git-2" title="No repositories" description="There are no repositories you can read in this tenant." />
      </Page>
    );
  }

  return (
    <Page id="flaky-tests" title={`Flaky tests · ${slug}`}>
      {nav}
      <form className="flex flex-wrap items-end gap-3" role="search" aria-label="Choose the flaky-test window" onSubmit={apply}>
        <Select id="f-repo" label="Repository" className="w-44" value={repoPick} onChange={setRepoPick}
          items={loaded.repos.repos.map((r) => ({ label: r.name, value: r.name }))} />
        <Select id="f-days" label="Window" className="w-36" value={days} onChange={setDays}
          items={FLAKE_WINDOWS.map((n) => ({ label: `${n} day${n === "1" ? "" : "s"}`, value: n }))} />
        <Button type="submit" icon="search" label="Show flaky tests" />
      </form>

      {failure ? <LoadFailed what="flaky tests" words={failure} /> : data ? (
        <>
          <section aria-labelledby="flaky-h" className="space-y-3">
            <h2 id="flaky-h" className="text-base font-semibold text-strong">Flaky tests in {loaded.repo}</h2>
            <p className="text-sm text-muted" id="flaky-note">
              A test is flaky when it failed on one attempt and passed on a later attempt of the <strong>same commit</strong>, so a
              rerun proved it. These are counts read from the runs' own JUnit and Go test reports, {data.window.days}{" "}
              day{data.window.days === 1 ? "" : "s"} back
              {data.window.oldest_ms !== null ? <> from <RelTime ms={data.window.oldest_ms} /> to <RelTime ms={data.window.newest_ms} /></> : null}.
              The rate is the share of the commits the test ran in on which it flaked.
            </p>
            {data.truncated ? <Alert color="warning" icon="info" role="status" description="The window holds more results than this repository's outcome rows keep; the figures cover the most recent ones." /> : null}
            {data.broken ? <Alert color="warning" icon="info" role="status" description={`${data.broken} further ${data.broken === 1 ? "test failed" : "tests failed"} on every attempt in the window: broken, not flaky, so ${data.broken === 1 ? "it is" : "they are"} not listed.`} /> : null}
            <Table caption={`Flaky tests of ${loaded.repo}, worst first`}>
              <thead>
                <tr>
                  <th>Test</th><th>Rate</th><th>Flaked commits</th><th>Failures</th><th>Last failure</th>
                </tr>
              </thead>
              <tbody>
                {data.tests.length ? data.tests.map((test) => (
                  <tr key={test.identity}>
                    <td>
                      <span className="font-medium text-strong">{test.name}</span>
                      {test.suite ? <span className="block text-xs text-muted">{test.suite}</span> : null}
                    </td>
                    <td title={`${test.flakes} of ${test.commits} commits`}>{fmtRate(test.rate_bps)}</td>
                    <td>{test.flakes} of {test.commits}</td>
                    <td>{test.failed} of {test.attempts} attempts</td>
                    <td><RelTime ms={test.last_failed_ms} /></td>
                  </tr>
                )) : <tr><td colSpan={5} className="text-center text-muted">No test flaked in this window.</td></tr>}
              </tbody>
            </Table>
          </section>
        </>
      ) : null}
    </Page>
  );
}
