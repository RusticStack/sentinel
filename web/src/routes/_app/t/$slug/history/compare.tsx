import { useEffect } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { api } from "../../../../../lib/api.ts";
import { attempt, useLoad, type Load } from "../../../../../lib/loaded.ts";
import { loadRepos } from "../../../../../lib/repos.ts";
import { ATTEMPT, NAME, searchSchema } from "../../../../../lib/search.ts";
import { fmtNs, shortId } from "../../../../../lib/format.ts";
import { PHASES, comparePath, fmtDelta, fmtShare, type CompareSide, type Comparison } from "../../../../../lib/history.ts";
import { Page, rememberTenant } from "../../../../../components/Page.tsx";
import { RelTime } from "../../../../../components/RelTime.tsx";
import { LoadFailed } from "../../../../../components/LoadFailed.tsx";
import { HistoryNav } from "../../../../../components/history/HistoryNav.tsx";
import { Alert, ButtonLink, Empty, Table, TextLink } from "../../../../../components/ui.tsx";

// The router passes on the parameters it could not validate too; the loader reads only the validated ones.
const schema = searchSchema({ repo: [NAME, 100], base: [ATTEMPT, 40], head: [ATTEMPT, 40] });

export const Route = createFileRoute("/_app/t/$slug/history/compare")({
  validateSearch: schema,
  loaderDeps: ({ search }) => schema["~standard"].validate(search).value,
  loader: async ({ params, deps }) => {
    const repos = await loadRepos(params.slug);
    const repo = deps.repo || repos.repos[0]?.name || null;
    if (!repo || !deps.base || !deps.head) return { repo, comparison: null as Load<Comparison> | null, gone: false };
    const comparison = await attempt(() => api<Comparison>(comparePath(params.slug, repo, deps.base!, deps.head!)));
    // An attempt of another repository answers as a missing one, which the page says without guessing which.
    return { repo, comparison, gone: comparison.failure !== null && comparison.failure.includes("not found") };
  },
  head: ({ params }) => ({ meta: [{ title: `Compare phases · ${params.slug} · Sentinel` }] }),
  component: CompareView,
});

function Side({ title, side, slug }: { title: string; side: CompareSide; slug: string }) {
  return (
    <div className="rounded-lg border border-line bg-canvas px-4 py-3">
      <h3 className="text-xs font-medium uppercase tracking-wide text-muted">{title}</h3>
      <p className="mt-1 text-sm">
        <TextLink to={`/runs/${side.run}`} className="font-medium">Run {shortId(side.run)}</TextLink>, <TextLink to={`/runs/${side.run}/logs/${side.attempt}`}>attempt {side.fence}</TextLink>
      </p>
      <p className="text-xs text-muted">Created <RelTime ms={side.created_ms} />{side.present ? "" : " · no phase timings reported yet"}</p>
      <p className="mt-1 text-2xl font-semibold text-strong">{fmtNs(side.total_ns)}</p>
      <p className="text-xs text-muted">duration</p>
    </div>
  );
}

function CompareView() {
  const { slug } = Route.useParams();
  const search = Route.useSearch();
  const loaded = Route.useLoaderData();
  const { data, failure } = useLoad<Comparison>(loaded.comparison ?? { value: null, failure: null });
  useEffect(() => { rememberTenant(slug); }, [slug]);
  const nav = <HistoryNav slug={slug} repo={loaded.repo} current="compare" />;

  if (!loaded.comparison) {
    return (
      <Page id="compare" title={`Compare phases · ${slug}`}>
        {nav}
        <Empty icon="git-merge" title="Choose two attempts" description="Open a job in the durations view and choose the two attempts to compare."
          actions={<ButtonLink to={`/t/${slug}/history`} search={loaded.repo ? { repo: loaded.repo } : undefined} color="neutral" variant="outline" label="Job durations" />} />
      </Page>
    );
  }
  if (failure || !data) {
    return (
      <Page id="compare" title={`Compare phases · ${slug}`}>
        {nav}
        {loaded.gone
          ? <Empty icon="git-merge" title="Attempts not found" description="One of the attempts is not in this repository, or does not exist." />
          : <LoadFailed what="the comparison" words={failure ?? "the controller did not answer"} />}
      </Page>
    );
  }
  const swap = { repo: loaded.repo!, base: search.head!, head: search.base! };
  const rows = [{ key: "total", label: "Duration", sub: false }, ...PHASES] as { key: string; label: string; sub: boolean }[];
  const time = (side: CompareSide, key: string) => (key === "total" ? side.total_ns : side.timings_ns?.[key as keyof typeof side.timings_ns]);

  return (
    <Page id="compare" title={`Compare phases of ${data.job}`}
      actions={<ButtonLink to={`/t/${slug}/history/compare`} search={swap} color="neutral" variant="outline" icon="arrow-left" label="Swap base and head" />}>
      {nav}
      <div className="grid gap-3 sm:grid-cols-2">
        <Side title="Base" side={data.base} slug={slug} />
        <Side title="Head" side={data.head} slug={slug} />
      </div>
      {!data.base.present || !data.head.present
        ? <Alert color="info" icon="info" role="status" description="An attempt that has not finished has no phase timings, so only the other side is shown and nothing is compared." /> : null}
      <section aria-labelledby="phases-h" className="space-y-3">
        <h2 id="phases-h" className="text-base font-semibold text-strong">Phase by phase</h2>
        <p className="text-sm text-muted">Change is the head minus the base, only where both measured the phase. Checkout and image pull run side by side, so the duration takes the longer of the two.</p>
        <Table caption={`Phases of ${data.job}, base against head`}>
          <thead><tr><th>Phase</th><th>Base</th><th>Head</th><th>Change</th></tr></thead>
          <tbody>
            {rows.map((r) => {
              const delta = data.delta_ns[r.key as keyof typeof data.delta_ns];
              const b = time(data.base, r.key);
              return (
                <tr key={r.key}>
                  <th scope="row" className={r.sub ? "pl-6 font-normal" : "font-medium"}>{r.label}</th>
                  <td>{fmtNs(b)}</td>
                  <td>{fmtNs(time(data.head, r.key))}</td>
                  <td>{fmtDelta(delta)} <span className="text-muted">{fmtShare(b, delta)}</span></td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      </section>
    </Page>
  );
}
